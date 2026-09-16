rule TTP_XOR_WriteProcessMemory_59cf {
  strings:
    $key_59cf = { 0e bd [2] 3c 9f [2] 3a aa [2] 14 aa [2] 2b b6 }

  condition:
    any of them
}