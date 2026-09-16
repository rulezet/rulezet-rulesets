rule TTP_XOR_WriteProcessMemory_a02c {
  strings:
    $key_a02c = { f7 5e [2] c5 7c [2] c3 49 [2] ed 49 [2] d2 55 }

  condition:
    any of them
}