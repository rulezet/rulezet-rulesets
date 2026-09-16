rule TTP_XOR_WriteProcessMemory_c886 {
  strings:
    $key_c886 = { 9f f4 [2] ad d6 [2] ab e3 [2] 85 e3 [2] ba ff }

  condition:
    any of them
}