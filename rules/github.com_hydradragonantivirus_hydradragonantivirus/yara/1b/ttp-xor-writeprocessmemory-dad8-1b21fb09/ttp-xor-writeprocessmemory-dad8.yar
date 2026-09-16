rule TTP_XOR_WriteProcessMemory_dad8 {
  strings:
    $key_dad8 = { 8d aa [2] bf 88 [2] b9 bd [2] 97 bd [2] a8 a1 }

  condition:
    any of them
}