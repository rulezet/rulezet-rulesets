rule TTP_XOR_WriteProcessMemory_dea8 {
  strings:
    $key_dea8 = { 89 da [2] bb f8 [2] bd cd [2] 93 cd [2] ac d1 }

  condition:
    any of them
}