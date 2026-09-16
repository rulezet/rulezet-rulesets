rule TTP_XOR_WriteProcessMemory_4fa3 {
  strings:
    $key_4fa3 = { 18 d1 [2] 2a f3 [2] 2c c6 [2] 02 c6 [2] 3d da }

  condition:
    any of them
}