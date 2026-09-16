rule TTP_XOR_WriteProcessMemory_f204 {
  strings:
    $key_f204 = { a5 76 [2] 97 54 [2] 91 61 [2] bf 61 [2] 80 7d }

  condition:
    any of them
}