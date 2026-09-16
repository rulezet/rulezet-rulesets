rule TTP_XOR_WriteProcessMemory_e6b6 {
  strings:
    $key_e6b6 = { b1 c4 [2] 83 e6 [2] 85 d3 [2] ab d3 [2] 94 cf }

  condition:
    any of them
}