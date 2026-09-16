rule TTP_XOR_WriteProcessMemory_4f96 {
  strings:
    $key_4f96 = { 18 e4 [2] 2a c6 [2] 2c f3 [2] 02 f3 [2] 3d ef }

  condition:
    any of them
}