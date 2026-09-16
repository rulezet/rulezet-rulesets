rule TTP_XOR_WriteProcessMemory_4815 {
  strings:
    $key_4815 = { 1f 67 [2] 2d 45 [2] 2b 70 [2] 05 70 [2] 3a 6c }

  condition:
    any of them
}