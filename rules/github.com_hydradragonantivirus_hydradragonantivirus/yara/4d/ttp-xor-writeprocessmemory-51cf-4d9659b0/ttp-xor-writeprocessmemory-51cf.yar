rule TTP_XOR_WriteProcessMemory_51cf {
  strings:
    $key_51cf = { 06 bd [2] 34 9f [2] 32 aa [2] 1c aa [2] 23 b6 }

  condition:
    any of them
}