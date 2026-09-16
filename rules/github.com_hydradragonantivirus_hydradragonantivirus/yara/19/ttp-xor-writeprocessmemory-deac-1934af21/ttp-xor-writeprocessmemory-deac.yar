rule TTP_XOR_WriteProcessMemory_deac {
  strings:
    $key_deac = { 89 de [2] bb fc [2] bd c9 [2] 93 c9 [2] ac d5 }

  condition:
    any of them
}