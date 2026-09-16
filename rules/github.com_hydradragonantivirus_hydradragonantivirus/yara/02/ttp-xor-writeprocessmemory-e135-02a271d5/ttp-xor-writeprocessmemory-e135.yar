rule TTP_XOR_WriteProcessMemory_e135 {
  strings:
    $key_e135 = { b6 47 [2] 84 65 [2] 82 50 [2] ac 50 [2] 93 4c }

  condition:
    any of them
}