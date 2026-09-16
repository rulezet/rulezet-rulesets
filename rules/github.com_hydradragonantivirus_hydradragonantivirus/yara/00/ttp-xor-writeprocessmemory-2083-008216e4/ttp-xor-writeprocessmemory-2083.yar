rule TTP_XOR_WriteProcessMemory_2083 {
  strings:
    $key_2083 = { 77 f1 [2] 45 d3 [2] 43 e6 [2] 6d e6 [2] 52 fa }

  condition:
    any of them
}