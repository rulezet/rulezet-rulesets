rule TTP_XOR_WriteProcessMemory_e160 {
  strings:
    $key_e160 = { b6 12 [2] 84 30 [2] 82 05 [2] ac 05 [2] 93 19 }

  condition:
    any of them
}