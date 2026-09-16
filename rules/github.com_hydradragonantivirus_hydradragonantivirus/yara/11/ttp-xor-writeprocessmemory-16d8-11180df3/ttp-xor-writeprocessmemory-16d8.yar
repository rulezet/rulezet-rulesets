rule TTP_XOR_WriteProcessMemory_16d8 {
  strings:
    $key_16d8 = { 41 aa [2] 73 88 [2] 75 bd [2] 5b bd [2] 64 a1 }

  condition:
    any of them
}