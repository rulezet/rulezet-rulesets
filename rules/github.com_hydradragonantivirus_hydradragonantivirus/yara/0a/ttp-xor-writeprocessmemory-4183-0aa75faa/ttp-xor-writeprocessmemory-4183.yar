rule TTP_XOR_WriteProcessMemory_4183 {
  strings:
    $key_4183 = { 16 f1 [2] 24 d3 [2] 22 e6 [2] 0c e6 [2] 33 fa }

  condition:
    any of them
}