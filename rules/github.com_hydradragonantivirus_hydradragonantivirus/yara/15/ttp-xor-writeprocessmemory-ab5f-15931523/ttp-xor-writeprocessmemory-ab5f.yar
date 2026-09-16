rule TTP_XOR_WriteProcessMemory_ab5f {
  strings:
    $key_ab5f = { fc 2d [2] ce 0f [2] c8 3a [2] e6 3a [2] d9 26 }

  condition:
    any of them
}