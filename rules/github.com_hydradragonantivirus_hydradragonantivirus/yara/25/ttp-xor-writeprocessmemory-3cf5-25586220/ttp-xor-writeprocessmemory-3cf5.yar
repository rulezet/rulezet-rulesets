rule TTP_XOR_WriteProcessMemory_3cf5 {
  strings:
    $key_3cf5 = { 6b 87 [2] 59 a5 [2] 5f 90 [2] 71 90 [2] 4e 8c }

  condition:
    any of them
}