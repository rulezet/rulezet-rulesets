rule TTP_XOR_WriteProcessMemory_75d8 {
  strings:
    $key_75d8 = { 22 aa [2] 10 88 [2] 16 bd [2] 38 bd [2] 07 a1 }

  condition:
    any of them
}