rule TTP_XOR_WriteProcessMemory_02d8 {
  strings:
    $key_02d8 = { 55 aa [2] 67 88 [2] 61 bd [2] 4f bd [2] 70 a1 }

  condition:
    any of them
}