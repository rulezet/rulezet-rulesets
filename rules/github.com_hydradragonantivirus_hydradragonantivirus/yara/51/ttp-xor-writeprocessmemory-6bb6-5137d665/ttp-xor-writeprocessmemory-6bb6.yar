rule TTP_XOR_WriteProcessMemory_6bb6 {
  strings:
    $key_6bb6 = { 3c c4 [2] 0e e6 [2] 08 d3 [2] 26 d3 [2] 19 cf }

  condition:
    any of them
}