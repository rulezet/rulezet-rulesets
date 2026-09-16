rule TTP_XOR_WriteProcessMemory_14d8 {
  strings:
    $key_14d8 = { 43 aa [2] 71 88 [2] 77 bd [2] 59 bd [2] 66 a1 }

  condition:
    any of them
}