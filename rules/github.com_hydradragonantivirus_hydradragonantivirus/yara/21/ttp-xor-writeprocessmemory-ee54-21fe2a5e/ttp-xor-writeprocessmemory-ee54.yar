rule TTP_XOR_WriteProcessMemory_ee54 {
  strings:
    $key_ee54 = { b9 26 [2] 8b 04 [2] 8d 31 [2] a3 31 [2] 9c 2d }

  condition:
    any of them
}