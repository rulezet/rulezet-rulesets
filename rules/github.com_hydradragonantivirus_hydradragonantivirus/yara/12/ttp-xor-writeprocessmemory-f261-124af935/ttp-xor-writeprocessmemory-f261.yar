rule TTP_XOR_WriteProcessMemory_f261 {
  strings:
    $key_f261 = { a5 13 [2] 97 31 [2] 91 04 [2] bf 04 [2] 80 18 }

  condition:
    any of them
}