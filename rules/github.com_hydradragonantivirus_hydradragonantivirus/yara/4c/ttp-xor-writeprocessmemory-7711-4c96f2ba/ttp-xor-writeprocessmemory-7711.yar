rule TTP_XOR_WriteProcessMemory_7711 {
  strings:
    $key_7711 = { 20 63 [2] 12 41 [2] 14 74 [2] 3a 74 [2] 05 68 }

  condition:
    any of them
}