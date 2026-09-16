rule TTP_XOR_WriteProcessMemory_2870 {
  strings:
    $key_2870 = { 7f 02 [2] 4d 20 [2] 4b 15 [2] 65 15 [2] 5a 09 }

  condition:
    any of them
}