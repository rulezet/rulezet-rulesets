rule TTP_XOR_WriteProcessMemory_b24c {
  strings:
    $key_b24c = { e5 3e [2] d7 1c [2] d1 29 [2] ff 29 [2] c0 35 }

  condition:
    any of them
}