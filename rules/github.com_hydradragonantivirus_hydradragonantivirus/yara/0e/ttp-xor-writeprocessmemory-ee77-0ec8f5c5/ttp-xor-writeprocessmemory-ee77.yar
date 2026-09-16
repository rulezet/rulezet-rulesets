rule TTP_XOR_WriteProcessMemory_ee77 {
  strings:
    $key_ee77 = { b9 05 [2] 8b 27 [2] 8d 12 [2] a3 12 [2] 9c 0e }

  condition:
    any of them
}