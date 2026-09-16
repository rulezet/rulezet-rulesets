rule TTP_XOR_WriteProcessMemory_3b93 {
  strings:
    $key_3b93 = { 6c e1 [2] 5e c3 [2] 58 f6 [2] 76 f6 [2] 49 ea }

  condition:
    any of them
}