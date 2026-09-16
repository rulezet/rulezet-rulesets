rule TTP_XOR_WriteProcessMemory_e1e3 {
  strings:
    $key_e1e3 = { b6 91 [2] 84 b3 [2] 82 86 [2] ac 86 [2] 93 9a }

  condition:
    any of them
}