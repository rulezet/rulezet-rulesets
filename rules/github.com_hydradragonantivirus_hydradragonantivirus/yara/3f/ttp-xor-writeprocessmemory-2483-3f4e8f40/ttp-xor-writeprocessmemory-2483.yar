rule TTP_XOR_WriteProcessMemory_2483 {
  strings:
    $key_2483 = { 73 f1 [2] 41 d3 [2] 47 e6 [2] 69 e6 [2] 56 fa }

  condition:
    any of them
}