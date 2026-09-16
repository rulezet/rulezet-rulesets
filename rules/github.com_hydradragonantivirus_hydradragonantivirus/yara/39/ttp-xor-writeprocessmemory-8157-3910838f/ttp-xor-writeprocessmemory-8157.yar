rule TTP_XOR_WriteProcessMemory_8157 {
  strings:
    $key_8157 = { d6 25 [2] e4 07 [2] e2 32 [2] cc 32 [2] f3 2e }

  condition:
    any of them
}