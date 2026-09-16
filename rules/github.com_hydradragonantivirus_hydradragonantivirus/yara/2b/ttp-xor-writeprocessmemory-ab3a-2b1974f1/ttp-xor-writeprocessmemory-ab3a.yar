rule TTP_XOR_WriteProcessMemory_ab3a {
  strings:
    $key_ab3a = { fc 48 [2] ce 6a [2] c8 5f [2] e6 5f [2] d9 43 }

  condition:
    any of them
}