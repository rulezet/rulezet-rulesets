rule TTP_XOR_WriteProcessMemory_2847 {
  strings:
    $key_2847 = { 7f 35 [2] 4d 17 [2] 4b 22 [2] 65 22 [2] 5a 3e }

  condition:
    any of them
}