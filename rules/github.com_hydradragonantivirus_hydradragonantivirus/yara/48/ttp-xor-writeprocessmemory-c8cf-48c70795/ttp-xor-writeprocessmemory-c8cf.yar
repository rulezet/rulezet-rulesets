rule TTP_XOR_WriteProcessMemory_c8cf {
  strings:
    $key_c8cf = { 9f bd [2] ad 9f [2] ab aa [2] 85 aa [2] ba b6 }

  condition:
    any of them
}