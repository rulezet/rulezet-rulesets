rule TTP_XOR_WriteProcessMemory_e59c {
  strings:
    $key_e59c = { b2 ee [2] 80 cc [2] 86 f9 [2] a8 f9 [2] 97 e5 }

  condition:
    any of them
}