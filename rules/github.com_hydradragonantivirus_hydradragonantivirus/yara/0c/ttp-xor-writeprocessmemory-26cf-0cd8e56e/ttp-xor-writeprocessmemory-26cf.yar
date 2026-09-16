rule TTP_XOR_WriteProcessMemory_26cf {
  strings:
    $key_26cf = { 71 bd [2] 43 9f [2] 45 aa [2] 6b aa [2] 54 b6 }

  condition:
    any of them
}