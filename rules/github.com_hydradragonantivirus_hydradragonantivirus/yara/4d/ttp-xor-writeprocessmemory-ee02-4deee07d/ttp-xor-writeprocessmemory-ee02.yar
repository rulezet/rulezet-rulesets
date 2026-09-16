rule TTP_XOR_WriteProcessMemory_ee02 {
  strings:
    $key_ee02 = { b9 70 [2] 8b 52 [2] 8d 67 [2] a3 67 [2] 9c 7b }

  condition:
    any of them
}