rule TTP_XOR_WriteProcessMemory_c970 {
  strings:
    $key_c970 = { 9e 02 [2] ac 20 [2] aa 15 [2] 84 15 [2] bb 09 }

  condition:
    any of them
}