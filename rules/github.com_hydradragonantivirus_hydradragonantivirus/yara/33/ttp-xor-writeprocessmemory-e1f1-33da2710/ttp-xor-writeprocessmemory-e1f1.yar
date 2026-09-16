rule TTP_XOR_WriteProcessMemory_e1f1 {
  strings:
    $key_e1f1 = { b6 83 [2] 84 a1 [2] 82 94 [2] ac 94 [2] 93 88 }

  condition:
    any of them
}