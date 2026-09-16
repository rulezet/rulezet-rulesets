rule TTP_XOR_WriteProcessMemory_7175 {
  strings:
    $key_7175 = { 26 07 [2] 14 25 [2] 12 10 [2] 3c 10 [2] 03 0c }

  condition:
    any of them
}