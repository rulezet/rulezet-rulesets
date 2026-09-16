rule TTP_XOR_WriteProcessMemory_3830 {
  strings:
    $key_3830 = { 6f 42 [2] 5d 60 [2] 5b 55 [2] 75 55 [2] 4a 49 }

  condition:
    any of them
}