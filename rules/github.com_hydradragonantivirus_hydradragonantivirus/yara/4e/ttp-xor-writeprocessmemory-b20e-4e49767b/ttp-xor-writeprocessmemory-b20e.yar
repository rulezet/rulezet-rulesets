rule TTP_XOR_WriteProcessMemory_b20e {
  strings:
    $key_b20e = { e5 7c [2] d7 5e [2] d1 6b [2] ff 6b [2] c0 77 }

  condition:
    any of them
}