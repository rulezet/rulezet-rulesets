rule TTP_XOR_WriteProcessMemory_3835 {
  strings:
    $key_3835 = { 6f 47 [2] 5d 65 [2] 5b 50 [2] 75 50 [2] 4a 4c }

  condition:
    any of them
}