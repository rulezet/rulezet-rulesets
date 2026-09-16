rule TTP_XOR_WriteProcessMemory_6683 {
  strings:
    $key_6683 = { 31 f1 [2] 03 d3 [2] 05 e6 [2] 2b e6 [2] 14 fa }

  condition:
    any of them
}