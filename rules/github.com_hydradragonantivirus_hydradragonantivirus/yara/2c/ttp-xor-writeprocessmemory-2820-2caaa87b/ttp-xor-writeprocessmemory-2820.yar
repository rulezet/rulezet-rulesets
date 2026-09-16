rule TTP_XOR_WriteProcessMemory_2820 {
  strings:
    $key_2820 = { 7f 52 [2] 4d 70 [2] 4b 45 [2] 65 45 [2] 5a 59 }

  condition:
    any of them
}