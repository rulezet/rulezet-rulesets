rule TTP_XOR_WriteProcessMemory_6893 {
  strings:
    $key_6893 = { 3f e1 [2] 0d c3 [2] 0b f6 [2] 25 f6 [2] 1a ea }

  condition:
    any of them
}