rule TTP_XOR_WriteProcessMemory_6a83 {
  strings:
    $key_6a83 = { 3d f1 [2] 0f d3 [2] 09 e6 [2] 27 e6 [2] 18 fa }

  condition:
    any of them
}