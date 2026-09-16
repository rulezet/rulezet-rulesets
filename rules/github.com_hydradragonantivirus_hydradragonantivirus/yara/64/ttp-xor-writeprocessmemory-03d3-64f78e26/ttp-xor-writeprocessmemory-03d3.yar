rule TTP_XOR_WriteProcessMemory_03d3 {
  strings:
    $key_03d3 = { 54 a1 [2] 66 83 [2] 60 b6 [2] 4e b6 [2] 71 aa }

  condition:
    any of them
}