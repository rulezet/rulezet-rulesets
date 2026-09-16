rule TTP_XOR_WriteProcessMemory_7ae5 {
  strings:
    $key_7ae5 = { 2d 97 [2] 1f b5 [2] 19 80 [2] 37 80 [2] 08 9c }

  condition:
    any of them
}