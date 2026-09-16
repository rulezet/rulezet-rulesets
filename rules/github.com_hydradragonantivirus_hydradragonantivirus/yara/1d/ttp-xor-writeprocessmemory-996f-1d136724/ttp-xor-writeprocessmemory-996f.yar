rule TTP_XOR_WriteProcessMemory_996f {
  strings:
    $key_996f = { ce 1d [2] fc 3f [2] fa 0a [2] d4 0a [2] eb 16 }

  condition:
    any of them
}