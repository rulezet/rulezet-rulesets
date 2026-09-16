rule TTP_XOR_WriteProcessMemory_dce5 {
  strings:
    $key_dce5 = { 8b 97 [2] b9 b5 [2] bf 80 [2] 91 80 [2] ae 9c }

  condition:
    any of them
}