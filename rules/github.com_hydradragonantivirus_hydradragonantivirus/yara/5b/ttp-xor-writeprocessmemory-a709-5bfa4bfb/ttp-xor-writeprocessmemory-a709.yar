rule TTP_XOR_WriteProcessMemory_a709 {
  strings:
    $key_a709 = { f0 7b [2] c2 59 [2] c4 6c [2] ea 6c [2] d5 70 }

  condition:
    any of them
}