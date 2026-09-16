rule TTP_XOR_WriteProcessMemory_f7d8 {
  strings:
    $key_f7d8 = { a0 aa [2] 92 88 [2] 94 bd [2] ba bd [2] 85 a1 }

  condition:
    any of them
}