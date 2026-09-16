rule TTP_XOR_WriteProcessMemory_94f5 {
  strings:
    $key_94f5 = { c3 87 [2] f1 a5 [2] f7 90 [2] d9 90 [2] e6 8c }

  condition:
    any of them
}