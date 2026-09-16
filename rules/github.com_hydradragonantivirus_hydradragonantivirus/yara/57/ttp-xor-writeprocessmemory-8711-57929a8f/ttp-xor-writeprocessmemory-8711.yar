rule TTP_XOR_WriteProcessMemory_8711 {
  strings:
    $key_8711 = { d0 63 [2] e2 41 [2] e4 74 [2] ca 74 [2] f5 68 }

  condition:
    any of them
}