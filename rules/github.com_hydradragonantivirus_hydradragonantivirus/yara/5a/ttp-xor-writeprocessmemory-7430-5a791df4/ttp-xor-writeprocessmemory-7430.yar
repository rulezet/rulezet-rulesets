rule TTP_XOR_WriteProcessMemory_7430 {
  strings:
    $key_7430 = { 23 42 [2] 11 60 [2] 17 55 [2] 39 55 [2] 06 49 }

  condition:
    any of them
}