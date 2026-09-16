rule TTP_XOR_WriteProcessMemory_64d3 {
  strings:
    $key_64d3 = { 33 a1 [2] 01 83 [2] 07 b6 [2] 29 b6 [2] 16 aa }

  condition:
    any of them
}