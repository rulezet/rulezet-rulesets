rule TTP_XOR_WriteProcessMemory_4f97 {
  strings:
    $key_4f97 = { 18 e5 [2] 2a c7 [2] 2c f2 [2] 02 f2 [2] 3d ee }

  condition:
    any of them
}