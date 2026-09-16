rule TTP_XOR_WriteProcessMemory_58b6 {
  strings:
    $key_58b6 = { 0f c4 [2] 3d e6 [2] 3b d3 [2] 15 d3 [2] 2a cf }

  condition:
    any of them
}