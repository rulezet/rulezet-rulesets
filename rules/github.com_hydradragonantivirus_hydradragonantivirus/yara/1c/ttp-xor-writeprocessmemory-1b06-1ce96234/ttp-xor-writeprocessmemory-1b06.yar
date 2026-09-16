rule TTP_XOR_WriteProcessMemory_1b06 {
  strings:
    $key_1b06 = { 4c 74 [2] 7e 56 [2] 78 63 [2] 56 63 [2] 69 7f }

  condition:
    any of them
}