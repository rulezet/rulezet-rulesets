rule TTP_XOR_WriteProcessMemory_e120 {
  strings:
    $key_e120 = { b6 52 [2] 84 70 [2] 82 45 [2] ac 45 [2] 93 59 }

  condition:
    any of them
}