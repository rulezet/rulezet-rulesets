rule TTP_XOR_WriteProcessMemory_e155 {
  strings:
    $key_e155 = { b6 27 [2] 84 05 [2] 82 30 [2] ac 30 [2] 93 2c }

  condition:
    any of them
}