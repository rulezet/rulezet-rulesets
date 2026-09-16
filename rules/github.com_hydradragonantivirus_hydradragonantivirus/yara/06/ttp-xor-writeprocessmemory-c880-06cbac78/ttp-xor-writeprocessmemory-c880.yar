rule TTP_XOR_WriteProcessMemory_c880 {
  strings:
    $key_c880 = { 9f f2 [2] ad d0 [2] ab e5 [2] 85 e5 [2] ba f9 }

  condition:
    any of them
}