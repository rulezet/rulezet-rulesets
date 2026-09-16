rule TTP_XOR_WriteProcessMemory_0696 {
  strings:
    $key_0696 = { 51 e4 [2] 63 c6 [2] 65 f3 [2] 4b f3 [2] 74 ef }

  condition:
    any of them
}