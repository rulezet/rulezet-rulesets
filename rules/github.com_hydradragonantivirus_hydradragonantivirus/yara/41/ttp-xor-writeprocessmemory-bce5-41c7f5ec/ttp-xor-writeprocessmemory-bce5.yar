rule TTP_XOR_WriteProcessMemory_bce5 {
  strings:
    $key_bce5 = { eb 97 [2] d9 b5 [2] df 80 [2] f1 80 [2] ce 9c }

  condition:
    any of them
}