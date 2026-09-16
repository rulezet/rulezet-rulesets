rule TTP_XOR_WriteProcessMemory_b23b {
  strings:
    $key_b23b = { e5 49 [2] d7 6b [2] d1 5e [2] ff 5e [2] c0 42 }

  condition:
    any of them
}