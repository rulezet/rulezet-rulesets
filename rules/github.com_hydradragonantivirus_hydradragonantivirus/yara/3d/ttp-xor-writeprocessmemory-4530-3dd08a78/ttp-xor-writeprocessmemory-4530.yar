rule TTP_XOR_WriteProcessMemory_4530 {
  strings:
    $key_4530 = { 12 42 [2] 20 60 [2] 26 55 [2] 08 55 [2] 37 49 }

  condition:
    any of them
}