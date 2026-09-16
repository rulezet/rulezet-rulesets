rule TTP_XOR_WriteProcessMemory_32b6 {
  strings:
    $key_32b6 = { 65 c4 [2] 57 e6 [2] 51 d3 [2] 7f d3 [2] 40 cf }

  condition:
    any of them
}