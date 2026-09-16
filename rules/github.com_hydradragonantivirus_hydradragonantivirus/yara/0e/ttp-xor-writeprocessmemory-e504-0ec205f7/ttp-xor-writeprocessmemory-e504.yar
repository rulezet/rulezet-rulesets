rule TTP_XOR_WriteProcessMemory_e504 {
  strings:
    $key_e504 = { b2 76 [2] 80 54 [2] 86 61 [2] a8 61 [2] 97 7d }

  condition:
    any of them
}