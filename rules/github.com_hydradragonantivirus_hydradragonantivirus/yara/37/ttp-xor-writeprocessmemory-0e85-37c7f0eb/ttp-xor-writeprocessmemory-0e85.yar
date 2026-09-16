rule TTP_XOR_WriteProcessMemory_0e85 {
  strings:
    $key_0e85 = { 59 f7 [2] 6b d5 [2] 6d e0 [2] 43 e0 [2] 7c fc }

  condition:
    any of them
}