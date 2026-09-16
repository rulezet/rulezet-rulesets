rule TTP_XOR_WriteProcessMemory_36cf {
  strings:
    $key_36cf = { 61 bd [2] 53 9f [2] 55 aa [2] 7b aa [2] 44 b6 }

  condition:
    any of them
}