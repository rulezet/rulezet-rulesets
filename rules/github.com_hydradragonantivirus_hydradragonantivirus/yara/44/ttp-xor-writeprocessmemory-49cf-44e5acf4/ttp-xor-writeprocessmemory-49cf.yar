rule TTP_XOR_WriteProcessMemory_49cf {
  strings:
    $key_49cf = { 1e bd [2] 2c 9f [2] 2a aa [2] 04 aa [2] 3b b6 }

  condition:
    any of them
}