rule TTP_XOR_WriteProcessMemory_b22e {
  strings:
    $key_b22e = { e5 5c [2] d7 7e [2] d1 4b [2] ff 4b [2] c0 57 }

  condition:
    any of them
}