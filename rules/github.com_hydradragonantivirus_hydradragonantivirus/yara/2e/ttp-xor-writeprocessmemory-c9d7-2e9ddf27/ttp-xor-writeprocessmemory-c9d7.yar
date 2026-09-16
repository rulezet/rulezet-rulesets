rule TTP_XOR_WriteProcessMemory_c9d7 {
  strings:
    $key_c9d7 = { 9e a5 [2] ac 87 [2] aa b2 [2] 84 b2 [2] bb ae }

  condition:
    any of them
}