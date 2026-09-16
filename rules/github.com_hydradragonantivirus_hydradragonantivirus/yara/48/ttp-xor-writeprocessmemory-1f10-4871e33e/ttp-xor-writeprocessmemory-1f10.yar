rule TTP_XOR_WriteProcessMemory_1f10 {
  strings:
    $key_1f10 = { 48 62 [2] 7a 40 [2] 7c 75 [2] 52 75 [2] 6d 69 }

  condition:
    any of them
}