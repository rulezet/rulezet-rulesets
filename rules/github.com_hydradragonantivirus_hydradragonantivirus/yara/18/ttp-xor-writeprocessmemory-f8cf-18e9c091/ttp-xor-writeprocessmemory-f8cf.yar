rule TTP_XOR_WriteProcessMemory_f8cf {
  strings:
    $key_f8cf = { af bd [2] 9d 9f [2] 9b aa [2] b5 aa [2] 8a b6 }

  condition:
    any of them
}