rule TTP_XOR_WriteProcessMemory_b22c {
  strings:
    $key_b22c = { e5 5e [2] d7 7c [2] d1 49 [2] ff 49 [2] c0 55 }

  condition:
    any of them
}