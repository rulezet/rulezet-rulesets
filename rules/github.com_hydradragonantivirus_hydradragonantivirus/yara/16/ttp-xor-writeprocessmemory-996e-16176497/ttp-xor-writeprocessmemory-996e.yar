rule TTP_XOR_WriteProcessMemory_996e {
  strings:
    $key_996e = { ce 1c [2] fc 3e [2] fa 0b [2] d4 0b [2] eb 17 }

  condition:
    any of them
}