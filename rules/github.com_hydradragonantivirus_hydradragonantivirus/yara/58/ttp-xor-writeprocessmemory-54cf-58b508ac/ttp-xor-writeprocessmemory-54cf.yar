rule TTP_XOR_WriteProcessMemory_54cf {
  strings:
    $key_54cf = { 03 bd [2] 31 9f [2] 37 aa [2] 19 aa [2] 26 b6 }

  condition:
    any of them
}