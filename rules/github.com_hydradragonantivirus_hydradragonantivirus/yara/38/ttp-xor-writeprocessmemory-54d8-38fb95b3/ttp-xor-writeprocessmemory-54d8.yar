rule TTP_XOR_WriteProcessMemory_54d8 {
  strings:
    $key_54d8 = { 03 aa [2] 31 88 [2] 37 bd [2] 19 bd [2] 26 a1 }

  condition:
    any of them
}