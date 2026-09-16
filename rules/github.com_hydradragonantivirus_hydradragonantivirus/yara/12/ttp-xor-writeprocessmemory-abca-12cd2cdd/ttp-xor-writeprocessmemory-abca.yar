rule TTP_XOR_WriteProcessMemory_abca {
  strings:
    $key_abca = { fc b8 [2] ce 9a [2] c8 af [2] e6 af [2] d9 b3 }

  condition:
    any of them
}