rule TTP_XOR_WriteProcessMemory_dcd8 {
  strings:
    $key_dcd8 = { 8b aa [2] b9 88 [2] bf bd [2] 91 bd [2] ae a1 }

  condition:
    any of them
}