rule TTP_XOR_WriteProcessMemory_5cf5 {
  strings:
    $key_5cf5 = { 0b 87 [2] 39 a5 [2] 3f 90 [2] 11 90 [2] 2e 8c }

  condition:
    any of them
}