rule TTP_XOR_WriteProcessMemory_7a35 {
  strings:
    $key_7a35 = { 2d 47 [2] 1f 65 [2] 19 50 [2] 37 50 [2] 08 4c }

  condition:
    any of them
}