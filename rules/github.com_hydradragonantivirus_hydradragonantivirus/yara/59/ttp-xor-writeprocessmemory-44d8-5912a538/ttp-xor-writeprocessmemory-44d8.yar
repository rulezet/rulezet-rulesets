rule TTP_XOR_WriteProcessMemory_44d8 {
  strings:
    $key_44d8 = { 13 aa [2] 21 88 [2] 27 bd [2] 09 bd [2] 36 a1 }

  condition:
    any of them
}