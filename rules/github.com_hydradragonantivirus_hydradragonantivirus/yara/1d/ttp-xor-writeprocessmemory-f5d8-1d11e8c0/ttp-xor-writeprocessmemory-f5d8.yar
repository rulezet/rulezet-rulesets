rule TTP_XOR_WriteProcessMemory_f5d8 {
  strings:
    $key_f5d8 = { a2 aa [2] 90 88 [2] 96 bd [2] b8 bd [2] 87 a1 }

  condition:
    any of them
}