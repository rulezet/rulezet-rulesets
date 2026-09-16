rule TTP_XOR_WriteProcessMemory_6d70 {
  strings:
    $key_6d70 = { 3a 02 [2] 08 20 [2] 0e 15 [2] 20 15 [2] 1f 09 }

  condition:
    any of them
}