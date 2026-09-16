rule TTP_XOR_WriteProcessMemory_5fcf {
  strings:
    $key_5fcf = { 08 bd [2] 3a 9f [2] 3c aa [2] 12 aa [2] 2d b6 }

  condition:
    any of them
}