rule TTP_XOR_WriteProcessMemory_b24e {
  strings:
    $key_b24e = { e5 3c [2] d7 1e [2] d1 2b [2] ff 2b [2] c0 37 }

  condition:
    any of them
}