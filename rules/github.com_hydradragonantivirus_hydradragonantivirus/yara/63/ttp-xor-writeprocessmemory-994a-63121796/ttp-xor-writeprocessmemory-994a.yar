rule TTP_XOR_WriteProcessMemory_994a {
  strings:
    $key_994a = { ce 38 [2] fc 1a [2] fa 2f [2] d4 2f [2] eb 33 }

  condition:
    any of them
}