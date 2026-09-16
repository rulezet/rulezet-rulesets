rule TTP_XOR_WriteProcessMemory_ab6f {
  strings:
    $key_ab6f = { fc 1d [2] ce 3f [2] c8 0a [2] e6 0a [2] d9 16 }

  condition:
    any of them
}