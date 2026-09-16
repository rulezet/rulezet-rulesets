rule TTP_XOR_WriteProcessMemory_6be5 {
  strings:
    $key_6be5 = { 3c 97 [2] 0e b5 [2] 08 80 [2] 26 80 [2] 19 9c }

  condition:
    any of them
}