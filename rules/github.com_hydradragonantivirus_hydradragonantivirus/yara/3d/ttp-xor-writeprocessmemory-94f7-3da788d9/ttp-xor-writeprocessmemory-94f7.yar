rule TTP_XOR_WriteProcessMemory_94f7 {
  strings:
    $key_94f7 = { c3 85 [2] f1 a7 [2] f7 92 [2] d9 92 [2] e6 8e }

  condition:
    any of them
}