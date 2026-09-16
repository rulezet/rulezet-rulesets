rule TTP_XOR_WriteProcessMemory_dec6 {
  strings:
    $key_dec6 = { 89 b4 [2] bb 96 [2] bd a3 [2] 93 a3 [2] ac bf }

  condition:
    any of them
}