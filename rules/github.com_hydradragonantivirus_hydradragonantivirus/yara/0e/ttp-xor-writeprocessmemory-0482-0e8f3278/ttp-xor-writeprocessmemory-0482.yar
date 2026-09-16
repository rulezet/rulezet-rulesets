rule TTP_XOR_WriteProcessMemory_0482 {
  strings:
    $key_0482 = { 53 f0 [2] 61 d2 [2] 67 e7 [2] 49 e7 [2] 76 fb }

  condition:
    any of them
}