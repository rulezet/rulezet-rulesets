rule TTP_XOR_WriteProcessMemory_e8f5 {
  strings:
    $key_e8f5 = { bf 87 [2] 8d a5 [2] 8b 90 [2] a5 90 [2] 9a 8c }

  condition:
    any of them
}