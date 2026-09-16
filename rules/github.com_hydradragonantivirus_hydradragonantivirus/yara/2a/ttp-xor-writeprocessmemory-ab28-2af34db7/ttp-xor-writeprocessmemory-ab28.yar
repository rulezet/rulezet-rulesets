rule TTP_XOR_WriteProcessMemory_ab28 {
  strings:
    $key_ab28 = { fc 5a [2] ce 78 [2] c8 4d [2] e6 4d [2] d9 51 }

  condition:
    any of them
}