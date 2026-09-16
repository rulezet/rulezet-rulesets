rule TTP_XOR_WriteProcessMemory_68cf {
  strings:
    $key_68cf = { 3f bd [2] 0d 9f [2] 0b aa [2] 25 aa [2] 1a b6 }

  condition:
    any of them
}