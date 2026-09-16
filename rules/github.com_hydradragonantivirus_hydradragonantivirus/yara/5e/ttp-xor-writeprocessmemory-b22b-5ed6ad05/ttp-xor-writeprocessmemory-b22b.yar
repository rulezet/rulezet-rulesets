rule TTP_XOR_WriteProcessMemory_b22b {
  strings:
    $key_b22b = { e5 59 [2] d7 7b [2] d1 4e [2] ff 4e [2] c0 52 }

  condition:
    any of them
}