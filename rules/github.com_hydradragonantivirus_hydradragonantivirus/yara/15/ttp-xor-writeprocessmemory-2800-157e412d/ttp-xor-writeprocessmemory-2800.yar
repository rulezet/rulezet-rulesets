rule TTP_XOR_WriteProcessMemory_2800 {
  strings:
    $key_2800 = { 7f 72 [2] 4d 50 [2] 4b 65 [2] 65 65 [2] 5a 79 }

  condition:
    any of them
}