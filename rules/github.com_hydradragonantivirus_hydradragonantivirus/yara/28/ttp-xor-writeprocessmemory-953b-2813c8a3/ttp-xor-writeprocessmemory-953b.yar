rule TTP_XOR_WriteProcessMemory_953b {
  strings:
    $key_953b = { c2 49 [2] f0 6b [2] f6 5e [2] d8 5e [2] e7 42 }

  condition:
    any of them
}