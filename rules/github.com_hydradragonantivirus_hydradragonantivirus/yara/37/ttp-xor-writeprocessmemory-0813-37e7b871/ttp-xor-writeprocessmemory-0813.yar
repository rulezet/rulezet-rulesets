rule TTP_XOR_WriteProcessMemory_0813 {
  strings:
    $key_0813 = { 5f 61 [2] 6d 43 [2] 6b 76 [2] 45 76 [2] 7a 6a }

  condition:
    any of them
}