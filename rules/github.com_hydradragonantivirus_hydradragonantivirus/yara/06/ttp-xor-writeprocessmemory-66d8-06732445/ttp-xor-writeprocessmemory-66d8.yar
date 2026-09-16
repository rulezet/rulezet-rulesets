rule TTP_XOR_WriteProcessMemory_66d8 {
  strings:
    $key_66d8 = { 31 aa [2] 03 88 [2] 05 bd [2] 2b bd [2] 14 a1 }

  condition:
    any of them
}