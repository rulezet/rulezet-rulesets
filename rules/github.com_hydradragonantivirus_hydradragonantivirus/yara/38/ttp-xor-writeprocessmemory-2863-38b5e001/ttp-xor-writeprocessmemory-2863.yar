rule TTP_XOR_WriteProcessMemory_2863 {
  strings:
    $key_2863 = { 7f 11 [2] 4d 33 [2] 4b 06 [2] 65 06 [2] 5a 1a }

  condition:
    any of them
}