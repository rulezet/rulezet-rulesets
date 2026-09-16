rule TTP_XOR_WriteProcessMemory_7cb6 {
  strings:
    $key_7cb6 = { 2b c4 [2] 19 e6 [2] 1f d3 [2] 31 d3 [2] 0e cf }

  condition:
    any of them
}