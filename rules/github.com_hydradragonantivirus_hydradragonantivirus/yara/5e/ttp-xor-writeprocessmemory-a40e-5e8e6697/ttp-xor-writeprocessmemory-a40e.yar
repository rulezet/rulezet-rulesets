rule TTP_XOR_WriteProcessMemory_a40e {
  strings:
    $key_a40e = { f3 7c [2] c1 5e [2] c7 6b [2] e9 6b [2] d6 77 }

  condition:
    any of them
}