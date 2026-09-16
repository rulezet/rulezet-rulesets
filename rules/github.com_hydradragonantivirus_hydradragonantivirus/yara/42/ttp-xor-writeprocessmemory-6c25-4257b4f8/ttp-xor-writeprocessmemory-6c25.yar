rule TTP_XOR_WriteProcessMemory_6c25 {
  strings:
    $key_6c25 = { 3b 57 [2] 09 75 [2] 0f 40 [2] 21 40 [2] 1e 5c }

  condition:
    any of them
}