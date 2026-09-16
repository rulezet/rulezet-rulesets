rule TTP_XOR_WriteProcessMemory_f633 {
  strings:
    $key_f633 = { a1 41 [2] 93 63 [2] 95 56 [2] bb 56 [2] 84 4a }

  condition:
    any of them
}