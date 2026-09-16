rule TTP_XOR_WriteProcessMemory_6913 {
  strings:
    $key_6913 = { 3e 61 [2] 0c 43 [2] 0a 76 [2] 24 76 [2] 1b 6a }

  condition:
    any of them
}