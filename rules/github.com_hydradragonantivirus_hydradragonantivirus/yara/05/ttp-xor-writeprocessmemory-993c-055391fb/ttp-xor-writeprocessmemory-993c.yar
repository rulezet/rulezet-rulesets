rule TTP_XOR_WriteProcessMemory_993c {
  strings:
    $key_993c = { ce 4e [2] fc 6c [2] fa 59 [2] d4 59 [2] eb 45 }

  condition:
    any of them
}