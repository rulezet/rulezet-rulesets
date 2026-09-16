rule TTP_XOR_WriteProcessMemory_33cf {
  strings:
    $key_33cf = { 64 bd [2] 56 9f [2] 50 aa [2] 7e aa [2] 41 b6 }

  condition:
    any of them
}