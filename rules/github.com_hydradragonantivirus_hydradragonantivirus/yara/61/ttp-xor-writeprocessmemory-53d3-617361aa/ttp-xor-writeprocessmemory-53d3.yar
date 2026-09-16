rule TTP_XOR_WriteProcessMemory_53d3 {
  strings:
    $key_53d3 = { 04 a1 [2] 36 83 [2] 30 b6 [2] 1e b6 [2] 21 aa }

  condition:
    any of them
}