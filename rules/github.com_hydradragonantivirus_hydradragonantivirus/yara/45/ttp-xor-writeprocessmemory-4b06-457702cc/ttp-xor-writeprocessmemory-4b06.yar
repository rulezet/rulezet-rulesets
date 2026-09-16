rule TTP_XOR_WriteProcessMemory_4b06 {
  strings:
    $key_4b06 = { 1c 74 [2] 2e 56 [2] 28 63 [2] 06 63 [2] 39 7f }

  condition:
    any of them
}