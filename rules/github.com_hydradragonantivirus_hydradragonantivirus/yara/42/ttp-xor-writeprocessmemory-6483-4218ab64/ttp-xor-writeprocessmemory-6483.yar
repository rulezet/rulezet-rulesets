rule TTP_XOR_WriteProcessMemory_6483 {
  strings:
    $key_6483 = { 33 f1 [2] 01 d3 [2] 07 e6 [2] 29 e6 [2] 16 fa }

  condition:
    any of them
}