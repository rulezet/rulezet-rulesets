rule TTP_XOR_WriteProcessMemory_55cf {
  strings:
    $key_55cf = { 02 bd [2] 30 9f [2] 36 aa [2] 18 aa [2] 27 b6 }

  condition:
    any of them
}