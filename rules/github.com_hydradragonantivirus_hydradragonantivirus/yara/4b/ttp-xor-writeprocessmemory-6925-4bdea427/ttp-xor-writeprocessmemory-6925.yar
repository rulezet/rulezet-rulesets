rule TTP_XOR_WriteProcessMemory_6925 {
  strings:
    $key_6925 = { 3e 57 [2] 0c 75 [2] 0a 40 [2] 24 40 [2] 1b 5c }

  condition:
    any of them
}