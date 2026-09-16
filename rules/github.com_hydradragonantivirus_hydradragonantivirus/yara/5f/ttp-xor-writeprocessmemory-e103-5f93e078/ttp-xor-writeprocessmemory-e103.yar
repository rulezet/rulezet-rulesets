rule TTP_XOR_WriteProcessMemory_e103 {
  strings:
    $key_e103 = { b6 71 [2] 84 53 [2] 82 66 [2] ac 66 [2] 93 7a }

  condition:
    any of them
}