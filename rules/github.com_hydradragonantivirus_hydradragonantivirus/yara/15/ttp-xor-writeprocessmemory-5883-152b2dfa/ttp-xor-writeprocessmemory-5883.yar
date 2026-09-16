rule TTP_XOR_WriteProcessMemory_5883 {
  strings:
    $key_5883 = { 0f f1 [2] 3d d3 [2] 3b e6 [2] 15 e6 [2] 2a fa }

  condition:
    any of them
}