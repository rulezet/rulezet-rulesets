rule TTP_XOR_WriteProcessMemory_0383 {
  strings:
    $key_0383 = { 54 f1 [2] 66 d3 [2] 60 e6 [2] 4e e6 [2] 71 fa }

  condition:
    any of them
}