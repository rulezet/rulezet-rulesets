rule TTP_XOR_WriteProcessMemory_28cf {
  strings:
    $key_28cf = { 7f bd [2] 4d 9f [2] 4b aa [2] 65 aa [2] 5a b6 }

  condition:
    any of them
}