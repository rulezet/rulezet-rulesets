rule TTP_XOR_WriteProcessMemory_4247 {
  strings:
    $key_4247 = { 15 35 [2] 27 17 [2] 21 22 [2] 0f 22 [2] 30 3e }

  condition:
    any of them
}