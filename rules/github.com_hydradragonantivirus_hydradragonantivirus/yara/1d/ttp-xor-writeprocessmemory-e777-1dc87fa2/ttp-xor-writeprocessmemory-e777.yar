rule TTP_XOR_WriteProcessMemory_e777 {
  strings:
    $key_e777 = { b0 05 [2] 82 27 [2] 84 12 [2] aa 12 [2] 95 0e }

  condition:
    any of them
}