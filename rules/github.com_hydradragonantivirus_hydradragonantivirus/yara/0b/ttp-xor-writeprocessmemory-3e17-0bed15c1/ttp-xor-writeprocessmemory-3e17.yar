rule TTP_XOR_WriteProcessMemory_3e17 {
  strings:
    $key_3e17 = { 69 65 [2] 5b 47 [2] 5d 72 [2] 73 72 [2] 4c 6e }

  condition:
    any of them
}