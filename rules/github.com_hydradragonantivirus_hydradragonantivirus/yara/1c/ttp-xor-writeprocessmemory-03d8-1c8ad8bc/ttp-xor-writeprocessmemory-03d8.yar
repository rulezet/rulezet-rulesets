rule TTP_XOR_WriteProcessMemory_03d8 {
  strings:
    $key_03d8 = { 54 aa [2] 66 88 [2] 60 bd [2] 4e bd [2] 71 a1 }

  condition:
    any of them
}