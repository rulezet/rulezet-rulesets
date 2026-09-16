rule TTP_XOR_WriteProcessMemory_c986 {
  strings:
    $key_c986 = { 9e f4 [2] ac d6 [2] aa e3 [2] 84 e3 [2] bb ff }

  condition:
    any of them
}