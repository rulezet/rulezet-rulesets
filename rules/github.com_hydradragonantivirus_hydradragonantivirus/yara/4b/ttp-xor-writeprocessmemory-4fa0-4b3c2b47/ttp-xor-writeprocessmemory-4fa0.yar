rule TTP_XOR_WriteProcessMemory_4fa0 {
  strings:
    $key_4fa0 = { 18 d2 [2] 2a f0 [2] 2c c5 [2] 02 c5 [2] 3d d9 }

  condition:
    any of them
}