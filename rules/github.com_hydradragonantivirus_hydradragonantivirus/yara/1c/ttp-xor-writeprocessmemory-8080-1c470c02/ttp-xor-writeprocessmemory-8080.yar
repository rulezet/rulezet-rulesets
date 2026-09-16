rule TTP_XOR_WriteProcessMemory_8080 {
  strings:
    $key_8080 = { d7 f2 [2] e5 d0 [2] e3 e5 [2] cd e5 [2] f2 f9 }

  condition:
    any of them
}