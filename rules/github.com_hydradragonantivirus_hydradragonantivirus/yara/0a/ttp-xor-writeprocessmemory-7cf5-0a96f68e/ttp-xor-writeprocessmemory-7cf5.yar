rule TTP_XOR_WriteProcessMemory_7cf5 {
  strings:
    $key_7cf5 = { 2b 87 [2] 19 a5 [2] 1f 90 [2] 31 90 [2] 0e 8c }

  condition:
    any of them
}