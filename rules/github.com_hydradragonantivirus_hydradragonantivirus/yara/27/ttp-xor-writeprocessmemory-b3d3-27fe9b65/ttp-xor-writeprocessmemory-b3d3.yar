rule TTP_XOR_WriteProcessMemory_b3d3 {
  strings:
    $key_b3d3 = { e4 a1 [2] d6 83 [2] d0 b6 [2] fe b6 [2] c1 aa }

  condition:
    any of them
}