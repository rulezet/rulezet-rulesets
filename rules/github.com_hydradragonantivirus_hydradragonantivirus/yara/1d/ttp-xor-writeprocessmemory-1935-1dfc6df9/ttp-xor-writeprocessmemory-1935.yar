rule TTP_XOR_WriteProcessMemory_1935 {
  strings:
    $key_1935 = { 4e 47 [2] 7c 65 [2] 7a 50 [2] 54 50 [2] 6b 4c }

  condition:
    any of them
}