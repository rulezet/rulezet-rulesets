rule TTP_XOR_WriteProcessMemory_ab1a {
  strings:
    $key_ab1a = { fc 68 [2] ce 4a [2] c8 7f [2] e6 7f [2] d9 63 }

  condition:
    any of them
}