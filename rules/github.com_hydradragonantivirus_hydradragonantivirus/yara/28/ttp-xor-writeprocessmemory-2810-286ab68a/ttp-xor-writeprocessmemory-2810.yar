rule TTP_XOR_WriteProcessMemory_2810 {
  strings:
    $key_2810 = { 7f 62 [2] 4d 40 [2] 4b 75 [2] 65 75 [2] 5a 69 }

  condition:
    any of them
}