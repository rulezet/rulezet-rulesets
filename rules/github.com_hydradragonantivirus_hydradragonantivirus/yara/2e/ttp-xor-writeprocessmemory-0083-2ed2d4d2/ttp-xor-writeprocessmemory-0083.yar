rule TTP_XOR_WriteProcessMemory_0083 {
  strings:
    $key_0083 = { 57 f1 [2] 65 d3 [2] 63 e6 [2] 4d e6 [2] 72 fa }

  condition:
    any of them
}