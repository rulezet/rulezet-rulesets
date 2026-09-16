rule TTP_XOR_WriteProcessMemory_decf {
  strings:
    $key_decf = { 89 bd [2] bb 9f [2] bd aa [2] 93 aa [2] ac b6 }

  condition:
    any of them
}