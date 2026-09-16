rule TTP_XOR_WriteProcessMemory_ab2a {
  strings:
    $key_ab2a = { fc 58 [2] ce 7a [2] c8 4f [2] e6 4f [2] d9 53 }

  condition:
    any of them
}