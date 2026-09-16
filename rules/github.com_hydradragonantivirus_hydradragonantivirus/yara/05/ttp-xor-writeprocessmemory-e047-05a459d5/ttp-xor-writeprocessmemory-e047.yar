rule TTP_XOR_WriteProcessMemory_e047 {
  strings:
    $key_e047 = { b7 35 [2] 85 17 [2] 83 22 [2] ad 22 [2] 92 3e }

  condition:
    any of them
}