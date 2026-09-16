rule TTP_XOR_WriteProcessMemory_ab6d {
  strings:
    $key_ab6d = { fc 1f [2] ce 3d [2] c8 08 [2] e6 08 [2] d9 14 }

  condition:
    any of them
}