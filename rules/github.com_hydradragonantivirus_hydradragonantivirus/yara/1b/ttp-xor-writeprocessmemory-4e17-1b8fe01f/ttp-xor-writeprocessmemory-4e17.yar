rule TTP_XOR_WriteProcessMemory_4e17 {
  strings:
    $key_4e17 = { 19 65 [2] 2b 47 [2] 2d 72 [2] 03 72 [2] 3c 6e }

  condition:
    any of them
}