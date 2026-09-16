rule TTP_XOR_WriteProcessMemory_e113 {
  strings:
    $key_e113 = { b6 61 [2] 84 43 [2] 82 76 [2] ac 76 [2] 93 6a }

  condition:
    any of them
}