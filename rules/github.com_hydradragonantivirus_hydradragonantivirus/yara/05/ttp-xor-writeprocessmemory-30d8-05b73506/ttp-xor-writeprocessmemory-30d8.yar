rule TTP_XOR_WriteProcessMemory_30d8 {
  strings:
    $key_30d8 = { 67 aa [2] 55 88 [2] 53 bd [2] 7d bd [2] 42 a1 }

  condition:
    any of them
}