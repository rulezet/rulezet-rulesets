rule TTP_XOR_WriteProcessMemory_52d3 {
  strings:
    $key_52d3 = { 05 a1 [2] 37 83 [2] 31 b6 [2] 1f b6 [2] 20 aa }

  condition:
    any of them
}