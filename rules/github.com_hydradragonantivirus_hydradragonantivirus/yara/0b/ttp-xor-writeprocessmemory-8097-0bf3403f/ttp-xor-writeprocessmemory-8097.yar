rule TTP_XOR_WriteProcessMemory_8097 {
  strings:
    $key_8097 = { d7 e5 [2] e5 c7 [2] e3 f2 [2] cd f2 [2] f2 ee }

  condition:
    any of them
}