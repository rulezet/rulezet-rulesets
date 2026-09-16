rule TTP_XOR_WriteProcessMemory_76d8 {
  strings:
    $key_76d8 = { 21 aa [2] 13 88 [2] 15 bd [2] 3b bd [2] 04 a1 }

  condition:
    any of them
}