rule TTP_XOR_WriteProcessMemory_04f5 {
  strings:
    $key_04f5 = { 53 87 [2] 61 a5 [2] 67 90 [2] 49 90 [2] 76 8c }

  condition:
    any of them
}