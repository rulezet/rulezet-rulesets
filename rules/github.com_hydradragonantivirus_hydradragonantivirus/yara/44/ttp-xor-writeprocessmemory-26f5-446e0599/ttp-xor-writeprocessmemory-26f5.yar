rule TTP_XOR_WriteProcessMemory_26f5 {
  strings:
    $key_26f5 = { 71 87 [2] 43 a5 [2] 45 90 [2] 6b 90 [2] 54 8c }

  condition:
    any of them
}