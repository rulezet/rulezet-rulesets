rule TTP_XOR_WriteProcessMemory_db86 {
  strings:
    $key_db86 = { 8c f4 [2] be d6 [2] b8 e3 [2] 96 e3 [2] a9 ff }

  condition:
    any of them
}