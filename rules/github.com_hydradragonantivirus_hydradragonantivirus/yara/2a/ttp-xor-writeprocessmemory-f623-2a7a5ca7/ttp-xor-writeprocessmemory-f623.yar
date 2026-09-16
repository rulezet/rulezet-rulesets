rule TTP_XOR_WriteProcessMemory_f623 {
  strings:
    $key_f623 = { a1 51 [2] 93 73 [2] 95 46 [2] bb 46 [2] 84 5a }

  condition:
    any of them
}