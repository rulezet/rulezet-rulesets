rule TTP_XOR_WriteProcessMemory_3783 {
  strings:
    $key_3783 = { 60 f1 [2] 52 d3 [2] 54 e6 [2] 7a e6 [2] 45 fa }

  condition:
    any of them
}