rule TTP_XOR_WriteProcessMemory_a739 {
  strings:
    $key_a739 = { f0 4b [2] c2 69 [2] c4 5c [2] ea 5c [2] d5 40 }

  condition:
    any of them
}