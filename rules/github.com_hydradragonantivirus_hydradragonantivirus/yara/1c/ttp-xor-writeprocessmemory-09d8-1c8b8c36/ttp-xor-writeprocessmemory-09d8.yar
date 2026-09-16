rule TTP_XOR_WriteProcessMemory_09d8 {
  strings:
    $key_09d8 = { 5e aa [2] 6c 88 [2] 6a bd [2] 44 bd [2] 7b a1 }

  condition:
    any of them
}