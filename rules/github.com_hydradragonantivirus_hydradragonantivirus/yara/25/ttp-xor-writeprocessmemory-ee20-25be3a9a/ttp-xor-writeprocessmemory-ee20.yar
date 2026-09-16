rule TTP_XOR_WriteProcessMemory_ee20 {
  strings:
    $key_ee20 = { b9 52 [2] 8b 70 [2] 8d 45 [2] a3 45 [2] 9c 59 }

  condition:
    any of them
}