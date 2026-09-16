rule TTP_XOR_WriteProcessMemory_f552 {
  strings:
    $key_f552 = { a2 20 [2] 90 02 [2] 96 37 [2] b8 37 [2] 87 2b }

  condition:
    any of them
}