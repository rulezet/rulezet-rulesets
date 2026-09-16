rule TTP_XOR_WriteProcessMemory_06e5 {
  strings:
    $key_06e5 = { 51 97 [2] 63 b5 [2] 65 80 [2] 4b 80 [2] 74 9c }

  condition:
    any of them
}