rule TTP_XOR_WriteProcessMemory_45cf {
  strings:
    $key_45cf = { 12 bd [2] 20 9f [2] 26 aa [2] 08 aa [2] 37 b6 }

  condition:
    any of them
}