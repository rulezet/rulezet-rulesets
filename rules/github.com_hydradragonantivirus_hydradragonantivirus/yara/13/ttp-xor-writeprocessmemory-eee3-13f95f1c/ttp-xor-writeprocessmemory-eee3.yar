rule TTP_XOR_WriteProcessMemory_eee3 {
  strings:
    $key_eee3 = { b9 91 [2] 8b b3 [2] 8d 86 [2] a3 86 [2] 9c 9a }

  condition:
    any of them
}