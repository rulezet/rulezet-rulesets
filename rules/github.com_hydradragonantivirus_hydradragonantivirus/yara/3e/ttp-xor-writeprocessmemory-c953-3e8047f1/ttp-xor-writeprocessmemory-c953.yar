rule TTP_XOR_WriteProcessMemory_c953 {
  strings:
    $key_c953 = { 9e 21 [2] ac 03 [2] aa 36 [2] 84 36 [2] bb 2a }

  condition:
    any of them
}