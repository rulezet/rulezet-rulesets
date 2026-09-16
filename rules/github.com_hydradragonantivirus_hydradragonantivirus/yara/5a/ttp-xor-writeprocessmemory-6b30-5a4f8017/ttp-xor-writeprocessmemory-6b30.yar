rule TTP_XOR_WriteProcessMemory_6b30 {
  strings:
    $key_6b30 = { 3c 42 [2] 0e 60 [2] 08 55 [2] 26 55 [2] 19 49 }

  condition:
    any of them
}