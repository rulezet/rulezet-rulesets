rule TTP_XOR_WriteProcessMemory_b27e {
  strings:
    $key_b27e = { e5 0c [2] d7 2e [2] d1 1b [2] ff 1b [2] c0 07 }

  condition:
    any of them
}