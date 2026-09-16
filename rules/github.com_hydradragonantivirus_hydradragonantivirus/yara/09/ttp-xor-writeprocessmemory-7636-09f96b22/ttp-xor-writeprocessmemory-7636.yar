rule TTP_XOR_WriteProcessMemory_7636 {
  strings:
    $key_7636 = { 21 44 [2] 13 66 [2] 15 53 [2] 3b 53 [2] 04 4f }

  condition:
    any of them
}