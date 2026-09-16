rule TTP_XOR_WriteProcessMemory_30cf {
  strings:
    $key_30cf = { 67 bd [2] 55 9f [2] 53 aa [2] 7d aa [2] 42 b6 }

  condition:
    any of them
}