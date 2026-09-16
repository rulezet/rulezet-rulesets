rule TTP_XOR_WriteProcessMemory_f9cf {
  strings:
    $key_f9cf = { ae bd [2] 9c 9f [2] 9a aa [2] b4 aa [2] 8b b6 }

  condition:
    any of them
}