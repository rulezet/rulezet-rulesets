rule TTP_XOR_WriteProcessMemory_3cd8 {
  strings:
    $key_3cd8 = { 6b aa [2] 59 88 [2] 5f bd [2] 71 bd [2] 4e a1 }

  condition:
    any of them
}