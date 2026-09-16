rule TTP_XOR_WriteProcessMemory_f510 {
  strings:
    $key_f510 = { a2 62 [2] 90 40 [2] 96 75 [2] b8 75 [2] 87 69 }

  condition:
    any of them
}