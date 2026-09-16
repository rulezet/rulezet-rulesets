rule TTP_XOR_WriteProcessMemory_69cf {
  strings:
    $key_69cf = { 3e bd [2] 0c 9f [2] 0a aa [2] 24 aa [2] 1b b6 }

  condition:
    any of them
}