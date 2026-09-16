rule TTP_XOR_WriteProcessMemory_73d3 {
  strings:
    $key_73d3 = { 24 a1 [2] 16 83 [2] 10 b6 [2] 3e b6 [2] 01 aa }

  condition:
    any of them
}