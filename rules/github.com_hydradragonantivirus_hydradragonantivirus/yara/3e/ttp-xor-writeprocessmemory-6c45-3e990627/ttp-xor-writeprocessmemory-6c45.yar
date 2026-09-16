rule TTP_XOR_WriteProcessMemory_6c45 {
  strings:
    $key_6c45 = { 3b 37 [2] 09 15 [2] 0f 20 [2] 21 20 [2] 1e 3c }

  condition:
    any of them
}