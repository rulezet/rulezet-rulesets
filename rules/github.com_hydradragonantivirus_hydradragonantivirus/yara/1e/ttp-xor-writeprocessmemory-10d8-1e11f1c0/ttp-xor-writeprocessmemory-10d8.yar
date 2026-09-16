rule TTP_XOR_WriteProcessMemory_10d8 {
  strings:
    $key_10d8 = { 47 aa [2] 75 88 [2] 73 bd [2] 5d bd [2] 62 a1 }

  condition:
    any of them
}