rule TTP_XOR_WriteProcessMemory_a769 {
  strings:
    $key_a769 = { f0 1b [2] c2 39 [2] c4 0c [2] ea 0c [2] d5 10 }

  condition:
    any of them
}