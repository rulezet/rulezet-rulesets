rule TTP_XOR_WriteProcessMemory_994c {
  strings:
    $key_994c = { ce 3e [2] fc 1c [2] fa 29 [2] d4 29 [2] eb 35 }

  condition:
    any of them
}