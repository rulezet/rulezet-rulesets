rule TTP_XOR_WriteProcessMemory_2841 {
  strings:
    $key_2841 = { 7f 33 [2] 4d 11 [2] 4b 24 [2] 65 24 [2] 5a 38 }

  condition:
    any of them
}