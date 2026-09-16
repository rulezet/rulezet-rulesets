rule TTP_XOR_WriteProcessMemory_7fcf {
  strings:
    $key_7fcf = { 28 bd [2] 1a 9f [2] 1c aa [2] 32 aa [2] 0d b6 }

  condition:
    any of them
}