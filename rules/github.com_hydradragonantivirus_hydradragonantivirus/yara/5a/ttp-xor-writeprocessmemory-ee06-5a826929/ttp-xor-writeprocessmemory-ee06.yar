rule TTP_XOR_WriteProcessMemory_ee06 {
  strings:
    $key_ee06 = { b9 74 [2] 8b 56 [2] 8d 63 [2] a3 63 [2] 9c 7f }

  condition:
    any of them
}