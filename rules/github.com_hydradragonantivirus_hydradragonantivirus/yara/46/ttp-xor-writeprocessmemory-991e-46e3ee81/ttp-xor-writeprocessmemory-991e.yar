rule TTP_XOR_WriteProcessMemory_991e {
  strings:
    $key_991e = { ce 6c [2] fc 4e [2] fa 7b [2] d4 7b [2] eb 67 }

  condition:
    any of them
}