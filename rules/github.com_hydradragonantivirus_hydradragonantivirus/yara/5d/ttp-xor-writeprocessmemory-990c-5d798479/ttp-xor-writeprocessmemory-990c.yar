rule TTP_XOR_WriteProcessMemory_990c {
  strings:
    $key_990c = { ce 7e [2] fc 5c [2] fa 69 [2] d4 69 [2] eb 75 }

  condition:
    any of them
}