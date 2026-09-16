rule TTP_XOR_WriteProcessMemory_0b93 {
  strings:
    $key_0b93 = { 5c e1 [2] 6e c3 [2] 68 f6 [2] 46 f6 [2] 79 ea }

  condition:
    any of them
}