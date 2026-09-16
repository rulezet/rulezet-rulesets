rule TTP_XOR_WriteProcessMemory_990d {
  strings:
    $key_990d = { ce 7f [2] fc 5d [2] fa 68 [2] d4 68 [2] eb 74 }

  condition:
    any of them
}