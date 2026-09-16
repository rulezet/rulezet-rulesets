rule TTP_XOR_WriteProcessMemory_48e5 {
  strings:
    $key_48e5 = { 1f 97 [2] 2d b5 [2] 2b 80 [2] 05 80 [2] 3a 9c }

  condition:
    any of them
}