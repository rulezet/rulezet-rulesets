rule TTP_XOR_WriteProcessMemory_c973 {
  strings:
    $key_c973 = { 9e 01 [2] ac 23 [2] aa 16 [2] 84 16 [2] bb 0a }

  condition:
    any of them
}