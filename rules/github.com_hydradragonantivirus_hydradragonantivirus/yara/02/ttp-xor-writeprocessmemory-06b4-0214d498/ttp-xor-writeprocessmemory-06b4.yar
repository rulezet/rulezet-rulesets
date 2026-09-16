rule TTP_XOR_WriteProcessMemory_06b4 {
  strings:
    $key_06b4 = { 51 c6 [2] 63 e4 [2] 65 d1 [2] 4b d1 [2] 74 cd }

  condition:
    any of them
}