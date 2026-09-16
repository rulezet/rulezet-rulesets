rule TTP_XOR_WriteProcessMemory_4434 {
  strings:
    $key_4434 = { 13 46 [2] 21 64 [2] 27 51 [2] 09 51 [2] 36 4d }

  condition:
    any of them
}