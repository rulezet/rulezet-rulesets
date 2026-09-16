rule TTP_XOR_WriteProcessMemory_e6d3 {
  strings:
    $key_e6d3 = { b1 a1 [2] 83 83 [2] 85 b6 [2] ab b6 [2] 94 aa }

  condition:
    any of them
}