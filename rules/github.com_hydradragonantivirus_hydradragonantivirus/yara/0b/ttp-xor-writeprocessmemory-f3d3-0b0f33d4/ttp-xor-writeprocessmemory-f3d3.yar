rule TTP_XOR_WriteProcessMemory_f3d3 {
  strings:
    $key_f3d3 = { a4 a1 [2] 96 83 [2] 90 b6 [2] be b6 [2] 81 aa }

  condition:
    any of them
}