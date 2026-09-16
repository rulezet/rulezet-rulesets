rule TTP_XOR_WriteProcessMemory_2970 {
  strings:
    $key_2970 = { 7e 02 [2] 4c 20 [2] 4a 15 [2] 64 15 [2] 5b 09 }

  condition:
    any of them
}