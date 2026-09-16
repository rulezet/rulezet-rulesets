rule TTP_XOR_WriteProcessMemory_1696 {
  strings:
    $key_1696 = { 41 e4 [2] 73 c6 [2] 75 f3 [2] 5b f3 [2] 64 ef }

  condition:
    any of them
}