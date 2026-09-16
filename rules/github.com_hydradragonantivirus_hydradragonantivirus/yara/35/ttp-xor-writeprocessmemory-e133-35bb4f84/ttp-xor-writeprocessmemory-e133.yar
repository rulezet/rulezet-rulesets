rule TTP_XOR_WriteProcessMemory_e133 {
  strings:
    $key_e133 = { b6 41 [2] 84 63 [2] 82 56 [2] ac 56 [2] 93 4a }

  condition:
    any of them
}