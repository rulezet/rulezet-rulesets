rule TTP_XOR_WriteProcessMemory_4711 {
  strings:
    $key_4711 = { 10 63 [2] 22 41 [2] 24 74 [2] 0a 74 [2] 35 68 }

  condition:
    any of them
}