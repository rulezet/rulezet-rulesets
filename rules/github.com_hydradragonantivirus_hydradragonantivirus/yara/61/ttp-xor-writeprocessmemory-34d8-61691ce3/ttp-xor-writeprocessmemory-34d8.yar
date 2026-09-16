rule TTP_XOR_WriteProcessMemory_34d8 {
  strings:
    $key_34d8 = { 63 aa [2] 51 88 [2] 57 bd [2] 79 bd [2] 46 a1 }

  condition:
    any of them
}