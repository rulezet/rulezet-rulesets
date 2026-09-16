rule TTP_XOR_WriteProcessMemory_e123 {
  strings:
    $key_e123 = { b6 51 [2] 84 73 [2] 82 46 [2] ac 46 [2] 93 5a }

  condition:
    any of them
}