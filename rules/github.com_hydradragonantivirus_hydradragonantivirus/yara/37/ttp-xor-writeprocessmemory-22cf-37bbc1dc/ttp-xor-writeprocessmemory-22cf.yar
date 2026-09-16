rule TTP_XOR_WriteProcessMemory_22cf {
  strings:
    $key_22cf = { 75 bd [2] 47 9f [2] 41 aa [2] 6f aa [2] 50 b6 }

  condition:
    any of them
}