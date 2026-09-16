rule TTP_XOR_WriteProcessMemory_a729 {
  strings:
    $key_a729 = { f0 5b [2] c2 79 [2] c4 4c [2] ea 4c [2] d5 50 }

  condition:
    any of them
}