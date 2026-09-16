rule TTP_XOR_WriteProcessMemory_f335 {
  strings:
    $key_f335 = { a4 47 [2] 96 65 [2] 90 50 [2] be 50 [2] 81 4c }

  condition:
    any of them
}