rule TTP_XOR_WriteProcessMemory_f514 {
  strings:
    $key_f514 = { a2 66 [2] 90 44 [2] 96 71 [2] b8 71 [2] 87 6d }

  condition:
    any of them
}