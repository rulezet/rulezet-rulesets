rule TTP_XOR_WriteProcessMemory_7a45 {
  strings:
    $key_7a45 = { 2d 37 [2] 1f 15 [2] 19 20 [2] 37 20 [2] 08 3c }

  condition:
    any of them
}