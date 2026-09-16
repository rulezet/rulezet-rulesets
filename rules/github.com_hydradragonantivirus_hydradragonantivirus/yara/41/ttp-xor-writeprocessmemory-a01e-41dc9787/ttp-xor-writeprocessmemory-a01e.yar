rule TTP_XOR_WriteProcessMemory_a01e {
  strings:
    $key_a01e = { f7 6c [2] c5 4e [2] c3 7b [2] ed 7b [2] d2 67 }

  condition:
    any of them
}