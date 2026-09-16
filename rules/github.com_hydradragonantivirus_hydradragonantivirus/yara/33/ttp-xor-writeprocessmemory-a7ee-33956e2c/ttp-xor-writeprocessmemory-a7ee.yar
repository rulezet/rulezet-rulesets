rule TTP_XOR_WriteProcessMemory_a7ee {
  strings:
    $key_a7ee = { f0 9c [2] c2 be [2] c4 8b [2] ea 8b [2] d5 97 }

  condition:
    any of them
}