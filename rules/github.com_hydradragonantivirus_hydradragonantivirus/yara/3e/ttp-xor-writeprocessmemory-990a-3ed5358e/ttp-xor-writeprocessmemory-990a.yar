rule TTP_XOR_WriteProcessMemory_990a {
  strings:
    $key_990a = { ce 78 [2] fc 5a [2] fa 6f [2] d4 6f [2] eb 73 }

  condition:
    any of them
}