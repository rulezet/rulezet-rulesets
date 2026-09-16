rule TTP_XOR_WriteProcessMemory_18cf {
  strings:
    $key_18cf = { 4f bd [2] 7d 9f [2] 7b aa [2] 55 aa [2] 6a b6 }

  condition:
    any of them
}