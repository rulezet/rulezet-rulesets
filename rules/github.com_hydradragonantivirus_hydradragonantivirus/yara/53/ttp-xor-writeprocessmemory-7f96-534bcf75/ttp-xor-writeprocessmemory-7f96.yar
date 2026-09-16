rule TTP_XOR_WriteProcessMemory_7f96 {
  strings:
    $key_7f96 = { 28 e4 [2] 1a c6 [2] 1c f3 [2] 32 f3 [2] 0d ef }

  condition:
    any of them
}