rule TTP_XOR_WriteProcessMemory_5bb6 {
  strings:
    $key_5bb6 = { 0c c4 [2] 3e e6 [2] 38 d3 [2] 16 d3 [2] 29 cf }

  condition:
    any of them
}