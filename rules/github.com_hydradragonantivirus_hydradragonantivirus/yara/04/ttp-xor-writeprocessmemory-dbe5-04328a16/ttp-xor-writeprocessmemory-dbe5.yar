rule TTP_XOR_WriteProcessMemory_dbe5 {
  strings:
    $key_dbe5 = { 8c 97 [2] be b5 [2] b8 80 [2] 96 80 [2] a9 9c }

  condition:
    any of them
}