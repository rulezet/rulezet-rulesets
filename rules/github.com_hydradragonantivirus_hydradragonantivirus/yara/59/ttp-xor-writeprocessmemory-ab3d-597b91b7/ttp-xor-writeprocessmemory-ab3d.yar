rule TTP_XOR_WriteProcessMemory_ab3d {
  strings:
    $key_ab3d = { fc 4f [2] ce 6d [2] c8 58 [2] e6 58 [2] d9 44 }

  condition:
    any of them
}