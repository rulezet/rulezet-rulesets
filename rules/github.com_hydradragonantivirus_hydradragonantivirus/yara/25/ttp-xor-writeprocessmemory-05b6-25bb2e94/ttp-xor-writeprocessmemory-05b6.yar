rule TTP_XOR_WriteProcessMemory_05b6 {
  strings:
    $key_05b6 = { 52 c4 [2] 60 e6 [2] 66 d3 [2] 48 d3 [2] 77 cf }

  condition:
    any of them
}