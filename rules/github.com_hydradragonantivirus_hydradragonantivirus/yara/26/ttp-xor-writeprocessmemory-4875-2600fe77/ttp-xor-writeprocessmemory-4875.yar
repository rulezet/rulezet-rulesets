rule TTP_XOR_WriteProcessMemory_4875 {
  strings:
    $key_4875 = { 1f 07 [2] 2d 25 [2] 2b 10 [2] 05 10 [2] 3a 0c }

  condition:
    any of them
}