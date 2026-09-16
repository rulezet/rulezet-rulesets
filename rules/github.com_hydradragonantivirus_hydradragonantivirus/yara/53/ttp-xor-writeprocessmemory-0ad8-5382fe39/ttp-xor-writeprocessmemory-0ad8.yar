rule TTP_XOR_WriteProcessMemory_0ad8 {
  strings:
    $key_0ad8 = { 5d aa [2] 6f 88 [2] 69 bd [2] 47 bd [2] 78 a1 }

  condition:
    any of them
}