rule TTP_XOR_WriteProcessMemory_46cf {
  strings:
    $key_46cf = { 11 bd [2] 23 9f [2] 25 aa [2] 0b aa [2] 34 b6 }

  condition:
    any of them
}