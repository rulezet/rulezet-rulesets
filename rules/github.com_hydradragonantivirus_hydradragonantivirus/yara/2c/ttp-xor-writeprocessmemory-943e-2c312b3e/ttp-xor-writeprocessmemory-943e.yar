rule TTP_XOR_WriteProcessMemory_943e {
  strings:
    $key_943e = { c3 4c [2] f1 6e [2] f7 5b [2] d9 5b [2] e6 47 }

  condition:
    any of them
}