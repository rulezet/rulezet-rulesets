rule TTP_XOR_WriteProcessMemory_ee34 {
  strings:
    $key_ee34 = { b9 46 [2] 8b 64 [2] 8d 51 [2] a3 51 [2] 9c 4d }

  condition:
    any of them
}