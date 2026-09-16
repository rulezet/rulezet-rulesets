rule TTP_XOR_WriteProcessMemory_f9d8 {
  strings:
    $key_f9d8 = { ae aa [2] 9c 88 [2] 9a bd [2] b4 bd [2] 8b a1 }

  condition:
    any of them
}