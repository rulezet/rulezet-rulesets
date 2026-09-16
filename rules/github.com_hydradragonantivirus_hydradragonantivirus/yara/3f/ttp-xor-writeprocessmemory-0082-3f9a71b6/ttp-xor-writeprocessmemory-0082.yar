rule TTP_XOR_WriteProcessMemory_0082 {
  strings:
    $key_0082 = { 57 f0 [2] 65 d2 [2] 63 e7 [2] 4d e7 [2] 72 fb }

  condition:
    any of them
}