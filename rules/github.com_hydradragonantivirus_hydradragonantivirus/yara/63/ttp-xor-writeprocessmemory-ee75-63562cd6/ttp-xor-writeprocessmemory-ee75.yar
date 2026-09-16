rule TTP_XOR_WriteProcessMemory_ee75 {
  strings:
    $key_ee75 = { b9 07 [2] 8b 25 [2] 8d 10 [2] a3 10 [2] 9c 0c }

  condition:
    any of them
}