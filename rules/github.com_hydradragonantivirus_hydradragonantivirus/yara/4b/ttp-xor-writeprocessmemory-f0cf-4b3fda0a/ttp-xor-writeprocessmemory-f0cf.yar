rule TTP_XOR_WriteProcessMemory_f0cf {
  strings:
    $key_f0cf = { a7 bd [2] 95 9f [2] 93 aa [2] bd aa [2] 82 b6 }

  condition:
    any of them
}