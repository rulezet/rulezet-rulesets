rule TTP_XOR_WriteProcessMemory_ee37 {
  strings:
    $key_ee37 = { b9 45 [2] 8b 67 [2] 8d 52 [2] a3 52 [2] 9c 4e }

  condition:
    any of them
}