rule TTP_XOR_WriteProcessMemory_e924 {
  strings:
    $key_e924 = { be 56 [2] 8c 74 [2] 8a 41 [2] a4 41 [2] 9b 5d }

  condition:
    any of them
}