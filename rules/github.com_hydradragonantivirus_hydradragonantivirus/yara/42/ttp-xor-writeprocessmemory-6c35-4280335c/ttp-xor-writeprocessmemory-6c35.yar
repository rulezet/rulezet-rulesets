rule TTP_XOR_WriteProcessMemory_6c35 {
  strings:
    $key_6c35 = { 3b 47 [2] 09 65 [2] 0f 50 [2] 21 50 [2] 1e 4c }

  condition:
    any of them
}