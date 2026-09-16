rule TTP_XOR_WriteProcessMemory_fed8 {
  strings:
    $key_fed8 = { a9 aa [2] 9b 88 [2] 9d bd [2] b3 bd [2] 8c a1 }

  condition:
    any of them
}