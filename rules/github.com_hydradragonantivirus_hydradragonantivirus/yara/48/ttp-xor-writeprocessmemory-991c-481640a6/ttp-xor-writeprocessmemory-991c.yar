rule TTP_XOR_WriteProcessMemory_991c {
  strings:
    $key_991c = { ce 6e [2] fc 4c [2] fa 79 [2] d4 79 [2] eb 65 }

  condition:
    any of them
}