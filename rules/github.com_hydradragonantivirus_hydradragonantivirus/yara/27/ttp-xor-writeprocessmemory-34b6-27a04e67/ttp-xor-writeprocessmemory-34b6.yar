rule TTP_XOR_WriteProcessMemory_34b6 {
  strings:
    $key_34b6 = { 63 c4 [2] 51 e6 [2] 57 d3 [2] 79 d3 [2] 46 cf }

  condition:
    any of them
}