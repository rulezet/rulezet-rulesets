rule TTP_XOR_WriteProcessMemory_04d3 {
  strings:
    $key_04d3 = { 53 a1 [2] 61 83 [2] 67 b6 [2] 49 b6 [2] 76 aa }

  condition:
    any of them
}