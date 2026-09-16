rule TTP_XOR_WriteProcessMemory_d7d8 {
  strings:
    $key_d7d8 = { 80 aa [2] b2 88 [2] b4 bd [2] 9a bd [2] a5 a1 }

  condition:
    any of them
}