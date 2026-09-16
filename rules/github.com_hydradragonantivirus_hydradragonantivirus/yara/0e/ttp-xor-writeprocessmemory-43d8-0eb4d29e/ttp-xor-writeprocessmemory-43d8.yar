rule TTP_XOR_WriteProcessMemory_43d8 {
  strings:
    $key_43d8 = { 14 aa [2] 26 88 [2] 20 bd [2] 0e bd [2] 31 a1 }

  condition:
    any of them
}