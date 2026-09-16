rule TTP_XOR_WriteProcessMemory_a72c {
  strings:
    $key_a72c = { f0 5e [2] c2 7c [2] c4 49 [2] ea 49 [2] d5 55 }

  condition:
    any of them
}