rule TTP_XOR_WriteProcessMemory_a9cf {
  strings:
    $key_a9cf = { fe bd [2] cc 9f [2] ca aa [2] e4 aa [2] db b6 }

  condition:
    any of them
}