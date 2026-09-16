rule TTP_XOR_WriteProcessMemory_c926 {
  strings:
    $key_c926 = { 9e 54 [2] ac 76 [2] aa 43 [2] 84 43 [2] bb 5f }

  condition:
    any of them
}