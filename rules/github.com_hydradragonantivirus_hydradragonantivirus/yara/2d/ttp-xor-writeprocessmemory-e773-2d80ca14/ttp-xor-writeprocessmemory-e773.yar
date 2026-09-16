rule TTP_XOR_WriteProcessMemory_e773 {
  strings:
    $key_e773 = { b0 01 [2] 82 23 [2] 84 16 [2] aa 16 [2] 95 0a }

  condition:
    any of them
}