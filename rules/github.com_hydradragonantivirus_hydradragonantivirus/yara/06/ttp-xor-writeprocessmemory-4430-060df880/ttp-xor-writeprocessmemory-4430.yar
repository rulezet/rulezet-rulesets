rule TTP_XOR_WriteProcessMemory_4430 {
  strings:
    $key_4430 = { 13 42 [2] 21 60 [2] 27 55 [2] 09 55 [2] 36 49 }

  condition:
    any of them
}