rule TTP_XOR_WriteProcessMemory_42d8 {
  strings:
    $key_42d8 = { 15 aa [2] 27 88 [2] 21 bd [2] 0f bd [2] 30 a1 }

  condition:
    any of them
}