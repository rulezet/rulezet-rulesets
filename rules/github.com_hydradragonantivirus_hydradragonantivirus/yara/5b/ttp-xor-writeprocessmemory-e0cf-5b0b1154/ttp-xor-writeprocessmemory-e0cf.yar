rule TTP_XOR_WriteProcessMemory_e0cf {
  strings:
    $key_e0cf = { b7 bd [2] 85 9f [2] 83 aa [2] ad aa [2] 92 b6 }

  condition:
    any of them
}