rule TTP_XOR_WriteProcessMemory_f214 {
  strings:
    $key_f214 = { a5 66 [2] 97 44 [2] 91 71 [2] bf 71 [2] 80 6d }

  condition:
    any of them
}