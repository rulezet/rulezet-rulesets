rule TTP_XOR_WriteProcessMemory_2696 {
  strings:
    $key_2696 = { 71 e4 [2] 43 c6 [2] 45 f3 [2] 6b f3 [2] 54 ef }

  condition:
    any of them
}