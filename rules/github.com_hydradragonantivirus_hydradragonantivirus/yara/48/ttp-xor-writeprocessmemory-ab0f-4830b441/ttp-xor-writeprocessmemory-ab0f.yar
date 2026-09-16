rule TTP_XOR_WriteProcessMemory_ab0f {
  strings:
    $key_ab0f = { fc 7d [2] ce 5f [2] c8 6a [2] e6 6a [2] d9 76 }

  condition:
    any of them
}