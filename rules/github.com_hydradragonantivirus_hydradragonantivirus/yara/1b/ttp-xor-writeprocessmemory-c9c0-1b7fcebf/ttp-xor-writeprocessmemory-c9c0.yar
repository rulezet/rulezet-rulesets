rule TTP_XOR_WriteProcessMemory_c9c0 {
  strings:
    $key_c9c0 = { 9e b2 [2] ac 90 [2] aa a5 [2] 84 a5 [2] bb b9 }

  condition:
    any of them
}