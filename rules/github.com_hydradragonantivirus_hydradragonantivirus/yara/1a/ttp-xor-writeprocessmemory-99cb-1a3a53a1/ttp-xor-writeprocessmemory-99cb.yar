rule TTP_XOR_WriteProcessMemory_99cb {
  strings:
    $key_99cb = { ce b9 [2] fc 9b [2] fa ae [2] d4 ae [2] eb b2 }

  condition:
    any of them
}