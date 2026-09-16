rule TTP_XOR_WriteProcessMemory_61cf {
  strings:
    $key_61cf = { 36 bd [2] 04 9f [2] 02 aa [2] 2c aa [2] 13 b6 }

  condition:
    any of them
}