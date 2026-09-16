rule TTP_XOR_WriteProcessMemory_7575 {
  strings:
    $key_7575 = { 22 07 [2] 10 25 [2] 16 10 [2] 38 10 [2] 07 0c }

  condition:
    any of them
}