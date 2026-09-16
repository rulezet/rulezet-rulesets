rule TTP_XOR_WriteProcessMemory_1db6 {
  strings:
    $key_1db6 = { 4a c4 [2] 78 e6 [2] 7e d3 [2] 50 d3 [2] 6f cf }

  condition:
    any of them
}