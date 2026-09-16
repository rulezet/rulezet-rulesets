rule TTP_XOR_WriteProcessMemory_c9c1 {
  strings:
    $key_c9c1 = { 9e b3 [2] ac 91 [2] aa a4 [2] 84 a4 [2] bb b8 }

  condition:
    any of them
}