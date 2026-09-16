rule TTP_XOR_WriteProcessMemory_ef42 {
  strings:
    $key_ef42 = { b8 30 [2] 8a 12 [2] 8c 27 [2] a2 27 [2] 9d 3b }

  condition:
    any of them
}