rule TTP_XOR_WriteProcessMemory_efe5 {
  strings:
    $key_efe5 = { b8 97 [2] 8a b5 [2] 8c 80 [2] a2 80 [2] 9d 9c }

  condition:
    any of them
}