rule TTP_XOR_WriteProcessMemory_86f5 {
  strings:
    $key_86f5 = { d1 87 [2] e3 a5 [2] e5 90 [2] cb 90 [2] f4 8c }

  condition:
    any of them
}