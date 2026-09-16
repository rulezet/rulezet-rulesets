rule TTP_XOR_WriteProcessMemory_5a75 {
  strings:
    $key_5a75 = { 0d 07 [2] 3f 25 [2] 39 10 [2] 17 10 [2] 28 0c }

  condition:
    any of them
}