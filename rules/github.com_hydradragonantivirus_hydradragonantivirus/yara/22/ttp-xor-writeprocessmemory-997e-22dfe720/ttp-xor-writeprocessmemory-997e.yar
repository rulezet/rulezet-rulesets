rule TTP_XOR_WriteProcessMemory_997e {
  strings:
    $key_997e = { ce 0c [2] fc 2e [2] fa 1b [2] d4 1b [2] eb 07 }

  condition:
    any of them
}