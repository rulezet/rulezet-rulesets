rule TTP_XOR_WriteProcessMemory_995f {
  strings:
    $key_995f = { ce 2d [2] fc 0f [2] fa 3a [2] d4 3a [2] eb 26 }

  condition:
    any of them
}