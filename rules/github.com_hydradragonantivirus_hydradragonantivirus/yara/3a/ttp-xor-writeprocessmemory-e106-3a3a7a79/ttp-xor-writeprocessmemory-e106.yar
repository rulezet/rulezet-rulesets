rule TTP_XOR_WriteProcessMemory_e106 {
  strings:
    $key_e106 = { b6 74 [2] 84 56 [2] 82 63 [2] ac 63 [2] 93 7f }

  condition:
    any of them
}