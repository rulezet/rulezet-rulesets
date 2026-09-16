rule TTP_XOR_WriteProcessMemory_cdd8 {
  strings:
    $key_cdd8 = { 9a aa [2] a8 88 [2] ae bd [2] 80 bd [2] bf a1 }

  condition:
    any of them
}