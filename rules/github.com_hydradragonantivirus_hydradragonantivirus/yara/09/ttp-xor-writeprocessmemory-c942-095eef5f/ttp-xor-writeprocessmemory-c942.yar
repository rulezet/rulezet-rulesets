rule TTP_XOR_WriteProcessMemory_c942 {
  strings:
    $key_c942 = { 9e 30 [2] ac 12 [2] aa 27 [2] 84 27 [2] bb 3b }

  condition:
    any of them
}