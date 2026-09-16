rule TTP_XOR_WriteProcessMemory_34cf {
  strings:
    $key_34cf = { 63 bd [2] 51 9f [2] 57 aa [2] 79 aa [2] 46 b6 }

  condition:
    any of them
}