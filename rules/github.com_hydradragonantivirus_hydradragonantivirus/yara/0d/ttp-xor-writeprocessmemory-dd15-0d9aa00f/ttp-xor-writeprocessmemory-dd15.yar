rule TTP_XOR_WriteProcessMemory_dd15 {
  strings:
    $key_dd15 = { 8a 67 [2] b8 45 [2] be 70 [2] 90 70 [2] af 6c }

  condition:
    any of them
}