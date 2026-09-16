rule TTP_XOR_WriteProcessMemory_2ad8 {
  strings:
    $key_2ad8 = { 7d aa [2] 4f 88 [2] 49 bd [2] 67 bd [2] 58 a1 }

  condition:
    any of them
}