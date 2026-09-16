rule TTP_XOR_WriteProcessMemory_2125 {
  strings:
    $key_2125 = { 76 57 [2] 44 75 [2] 42 40 [2] 6c 40 [2] 53 5c }

  condition:
    any of them
}