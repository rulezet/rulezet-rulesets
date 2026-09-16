rule TTP_XOR_WriteProcessMemory_3b13 {
  strings:
    $key_3b13 = { 6c 61 [2] 5e 43 [2] 58 76 [2] 76 76 [2] 49 6a }

  condition:
    any of them
}