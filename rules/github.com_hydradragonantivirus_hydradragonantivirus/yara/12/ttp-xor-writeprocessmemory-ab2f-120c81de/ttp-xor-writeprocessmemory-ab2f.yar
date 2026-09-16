rule TTP_XOR_WriteProcessMemory_ab2f {
  strings:
    $key_ab2f = { fc 5d [2] ce 7f [2] c8 4a [2] e6 4a [2] d9 56 }

  condition:
    any of them
}