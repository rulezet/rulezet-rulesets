rule TTP_XOR_WriteProcessMemory_5cb6 {
  strings:
    $key_5cb6 = { 0b c4 [2] 39 e6 [2] 3f d3 [2] 11 d3 [2] 2e cf }

  condition:
    any of them
}