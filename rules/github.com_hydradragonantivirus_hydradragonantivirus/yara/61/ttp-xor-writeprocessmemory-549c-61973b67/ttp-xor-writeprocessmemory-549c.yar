rule TTP_XOR_WriteProcessMemory_549c {
  strings:
    $key_549c = { 03 ee [2] 31 cc [2] 37 f9 [2] 19 f9 [2] 26 e5 }

  condition:
    any of them
}