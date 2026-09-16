rule TTP_XOR_WriteProcessMemory_3430 {
  strings:
    $key_3430 = { 63 42 [2] 51 60 [2] 57 55 [2] 79 55 [2] 46 49 }

  condition:
    any of them
}