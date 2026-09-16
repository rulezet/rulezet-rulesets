rule TTP_XOR_WriteProcessMemory_77cf {
  strings:
    $key_77cf = { 20 bd [2] 12 9f [2] 14 aa [2] 3a aa [2] 05 b6 }

  condition:
    any of them
}