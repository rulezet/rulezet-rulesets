rule TTP_XOR_WriteProcessMemory_efb6 {
  strings:
    $key_efb6 = { b8 c4 [2] 8a e6 [2] 8c d3 [2] a2 d3 [2] 9d cf }

  condition:
    any of them
}