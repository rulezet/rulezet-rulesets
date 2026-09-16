rule TTP_XOR_WriteProcessMemory_e0d3 {
  strings:
    $key_e0d3 = { b7 a1 [2] 85 83 [2] 83 b6 [2] ad b6 [2] 92 aa }

  condition:
    any of them
}