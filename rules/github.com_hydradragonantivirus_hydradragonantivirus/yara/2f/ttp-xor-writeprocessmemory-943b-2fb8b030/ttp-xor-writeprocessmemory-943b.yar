rule TTP_XOR_WriteProcessMemory_943b {
  strings:
    $key_943b = { c3 49 [2] f1 6b [2] f7 5e [2] d9 5e [2] e6 42 }

  condition:
    any of them
}