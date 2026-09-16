rule TTP_XOR_WriteProcessMemory_f211 {
  strings:
    $key_f211 = { a5 63 [2] 97 41 [2] 91 74 [2] bf 74 [2] 80 68 }

  condition:
    any of them
}