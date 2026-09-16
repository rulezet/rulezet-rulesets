rule TTP_XOR_WriteProcessMemory_ee66 {
  strings:
    $key_ee66 = { b9 14 [2] 8b 36 [2] 8d 03 [2] a3 03 [2] 9c 1f }

  condition:
    any of them
}