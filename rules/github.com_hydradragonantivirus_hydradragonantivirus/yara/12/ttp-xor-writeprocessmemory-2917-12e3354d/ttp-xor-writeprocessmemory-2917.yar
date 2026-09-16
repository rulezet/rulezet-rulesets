rule TTP_XOR_WriteProcessMemory_2917 {
  strings:
    $key_2917 = { 7e 65 [2] 4c 47 [2] 4a 72 [2] 64 72 [2] 5b 6e }

  condition:
    any of them
}