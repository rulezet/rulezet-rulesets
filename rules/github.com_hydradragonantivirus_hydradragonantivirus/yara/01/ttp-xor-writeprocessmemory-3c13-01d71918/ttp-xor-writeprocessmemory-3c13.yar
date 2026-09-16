rule TTP_XOR_WriteProcessMemory_3c13 {
  strings:
    $key_3c13 = { 6b 61 [2] 59 43 [2] 5f 76 [2] 71 76 [2] 4e 6a }

  condition:
    any of them
}