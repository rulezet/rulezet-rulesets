rule TTP_XOR_WriteProcessMemory_37b6 {
  strings:
    $key_37b6 = { 60 c4 [2] 52 e6 [2] 54 d3 [2] 7a d3 [2] 45 cf }

  condition:
    any of them
}