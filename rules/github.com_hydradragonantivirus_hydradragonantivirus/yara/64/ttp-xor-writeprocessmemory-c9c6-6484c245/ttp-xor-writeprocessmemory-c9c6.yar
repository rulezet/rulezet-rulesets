rule TTP_XOR_WriteProcessMemory_c9c6 {
  strings:
    $key_c9c6 = { 9e b4 [2] ac 96 [2] aa a3 [2] 84 a3 [2] bb bf }

  condition:
    any of them
}