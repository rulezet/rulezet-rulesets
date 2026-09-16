rule TTP_XOR_WriteProcessMemory_ee42 {
  strings:
    $key_ee42 = { b9 30 [2] 8b 12 [2] 8d 27 [2] a3 27 [2] 9c 3b }

  condition:
    any of them
}