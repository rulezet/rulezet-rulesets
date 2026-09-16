rule TTP_XOR_WriteProcessMemory_ab18 {
  strings:
    $key_ab18 = { fc 6a [2] ce 48 [2] c8 7d [2] e6 7d [2] d9 61 }

  condition:
    any of them
}