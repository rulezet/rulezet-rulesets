rule TTP_XOR_WriteProcessMemory_5a10 {
  strings:
    $key_5a10 = { 0d 62 [2] 3f 40 [2] 39 75 [2] 17 75 [2] 28 69 }

  condition:
    any of them
}