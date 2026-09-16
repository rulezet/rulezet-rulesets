rule TTP_XOR_WriteProcessMemory_21cf {
  strings:
    $key_21cf = { 76 bd [2] 44 9f [2] 42 aa [2] 6c aa [2] 53 b6 }

  condition:
    any of them
}