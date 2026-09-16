rule TTP_XOR_WriteProcessMemory_3817 {
  strings:
    $key_3817 = { 6f 65 [2] 5d 47 [2] 5b 72 [2] 75 72 [2] 4a 6e }

  condition:
    any of them
}