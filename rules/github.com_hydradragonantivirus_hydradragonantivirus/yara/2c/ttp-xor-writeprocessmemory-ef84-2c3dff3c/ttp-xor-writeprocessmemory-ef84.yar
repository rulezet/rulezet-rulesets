rule TTP_XOR_WriteProcessMemory_ef84 {
  strings:
    $key_ef84 = { b8 f6 [2] 8a d4 [2] 8c e1 [2] a2 e1 [2] 9d fd }

  condition:
    any of them
}