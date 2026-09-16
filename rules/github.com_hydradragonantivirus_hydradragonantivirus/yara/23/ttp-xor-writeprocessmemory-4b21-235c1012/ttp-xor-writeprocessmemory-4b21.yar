rule TTP_XOR_WriteProcessMemory_4b21 {
  strings:
    $key_4b21 = { 1c 53 [2] 2e 71 [2] 28 44 [2] 06 44 [2] 39 58 }

  condition:
    any of them
}