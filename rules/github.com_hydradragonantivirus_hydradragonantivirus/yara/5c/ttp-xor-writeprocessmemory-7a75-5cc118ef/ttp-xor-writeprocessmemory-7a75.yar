rule TTP_XOR_WriteProcessMemory_7a75 {
  strings:
    $key_7a75 = { 2d 07 [2] 1f 25 [2] 19 10 [2] 37 10 [2] 08 0c }

  condition:
    any of them
}