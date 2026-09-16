rule TTP_XOR_WriteProcessMemory_b729 {
  strings:
    $key_b729 = { e0 5b [2] d2 79 [2] d4 4c [2] fa 4c [2] c5 50 }

  condition:
    any of them
}