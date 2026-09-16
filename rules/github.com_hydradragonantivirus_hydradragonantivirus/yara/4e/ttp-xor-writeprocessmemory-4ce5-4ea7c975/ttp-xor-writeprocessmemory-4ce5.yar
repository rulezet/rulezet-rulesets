rule TTP_XOR_WriteProcessMemory_4ce5 {
  strings:
    $key_4ce5 = { 1b 97 [2] 29 b5 [2] 2f 80 [2] 01 80 [2] 3e 9c }

  condition:
    any of them
}