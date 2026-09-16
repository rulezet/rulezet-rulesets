rule TTP_XOR_WriteProcessMemory_947b {
  strings:
    $key_947b = { c3 09 [2] f1 2b [2] f7 1e [2] d9 1e [2] e6 02 }

  condition:
    any of them
}