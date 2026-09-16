rule TTP_XOR_WriteProcessMemory_d0d8 {
  strings:
    $key_d0d8 = { 87 aa [2] b5 88 [2] b3 bd [2] 9d bd [2] a2 a1 }

  condition:
    any of them
}