rule TTP_XOR_WriteProcessMemory_d6d8 {
  strings:
    $key_d6d8 = { 81 aa [2] b3 88 [2] b5 bd [2] 9b bd [2] a4 a1 }

  condition:
    any of them
}