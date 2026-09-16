rule TTP_XOR_WriteProcessMemory_f724 {
  strings:
    $key_f724 = { a0 56 [2] 92 74 [2] 94 41 [2] ba 41 [2] 85 5d }

  condition:
    any of them
}