rule TTP_XOR_WriteProcessMemory_ee05 {
  strings:
    $key_ee05 = { b9 77 [2] 8b 55 [2] 8d 60 [2] a3 60 [2] 9c 7c }

  condition:
    any of them
}