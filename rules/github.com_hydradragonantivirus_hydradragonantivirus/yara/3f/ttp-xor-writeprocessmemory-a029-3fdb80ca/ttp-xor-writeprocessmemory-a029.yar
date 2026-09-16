rule TTP_XOR_WriteProcessMemory_a029 {
  strings:
    $key_a029 = { f7 5b [2] c5 79 [2] c3 4c [2] ed 4c [2] d2 50 }

  condition:
    any of them
}