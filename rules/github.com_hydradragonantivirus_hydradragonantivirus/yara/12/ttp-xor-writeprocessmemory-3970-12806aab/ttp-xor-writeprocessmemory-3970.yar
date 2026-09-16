rule TTP_XOR_WriteProcessMemory_3970 {
  strings:
    $key_3970 = { 6e 02 [2] 5c 20 [2] 5a 15 [2] 74 15 [2] 4b 09 }

  condition:
    any of them
}