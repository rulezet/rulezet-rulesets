rule TTP_XOR_WriteProcessMemory_a019 {
  strings:
    $key_a019 = { f7 6b [2] c5 49 [2] c3 7c [2] ed 7c [2] d2 60 }

  condition:
    any of them
}