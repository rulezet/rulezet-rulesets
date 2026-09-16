rule TTP_XOR_WriteProcessMemory_e1b9 {
  strings:
    $key_e1b9 = { b6 cb [2] 84 e9 [2] 82 dc [2] ac dc [2] 93 c0 }

  condition:
    any of them
}