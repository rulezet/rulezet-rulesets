rule TTP_XOR_WriteProcessMemory_ef75 {
  strings:
    $key_ef75 = { b8 07 [2] 8a 25 [2] 8c 10 [2] a2 10 [2] 9d 0c }

  condition:
    any of them
}