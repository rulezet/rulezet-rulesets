rule TTP_XOR_WriteProcessMemory_277d {
  strings:
    $key_277d = { 70 0f [2] 42 2d [2] 44 18 [2] 6a 18 [2] 55 04 }

  condition:
    any of them
}