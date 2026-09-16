rule TTP_XOR_WriteProcessMemory_64cf {
  strings:
    $key_64cf = { 33 bd [2] 01 9f [2] 07 aa [2] 29 aa [2] 16 b6 }

  condition:
    any of them
}