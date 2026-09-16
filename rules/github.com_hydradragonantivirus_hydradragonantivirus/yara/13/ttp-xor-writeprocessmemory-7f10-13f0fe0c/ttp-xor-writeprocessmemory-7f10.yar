rule TTP_XOR_WriteProcessMemory_7f10 {
  strings:
    $key_7f10 = { 28 62 [2] 1a 40 [2] 1c 75 [2] 32 75 [2] 0d 69 }

  condition:
    any of them
}