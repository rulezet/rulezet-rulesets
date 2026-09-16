rule TTP_XOR_WriteProcessMemory_7c35 {
  strings:
    $key_7c35 = { 2b 47 [2] 19 65 [2] 1f 50 [2] 31 50 [2] 0e 4c }

  condition:
    any of them
}