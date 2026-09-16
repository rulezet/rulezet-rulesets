rule TTP_XOR_WriteProcessMemory_7090 {
  strings:
    $key_7090 = { 27 e2 [2] 15 c0 [2] 13 f5 [2] 3d f5 [2] 02 e9 }

  condition:
    any of them
}