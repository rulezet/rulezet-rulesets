rule TTP_XOR_WriteProcessMemory_c925 {
  strings:
    $key_c925 = { 9e 57 [2] ac 75 [2] aa 40 [2] 84 40 [2] bb 5c }

  condition:
    any of them
}