rule TTP_XOR_WriteProcessMemory_3711 {
  strings:
    $key_3711 = { 60 63 [2] 52 41 [2] 54 74 [2] 7a 74 [2] 45 68 }

  condition:
    any of them
}