rule TTP_XOR_WriteProcessMemory_ab5a {
  strings:
    $key_ab5a = { fc 28 [2] ce 0a [2] c8 3f [2] e6 3f [2] d9 23 }

  condition:
    any of them
}