rule TTP_XOR_WriteProcessMemory_0de5 {
  strings:
    $key_0de5 = { 5a 97 [2] 68 b5 [2] 6e 80 [2] 40 80 [2] 7f 9c }

  condition:
    any of them
}