rule TTP_XOR_WriteProcessMemory_8315 {
  strings:
    $key_8315 = { d4 67 [2] e6 45 [2] e0 70 [2] ce 70 [2] f1 6c }

  condition:
    any of them
}