rule TTP_XOR_WriteProcessMemory_e121 {
  strings:
    $key_e121 = { b6 53 [2] 84 71 [2] 82 44 [2] ac 44 [2] 93 58 }

  condition:
    any of them
}