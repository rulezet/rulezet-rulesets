rule TTP_XOR_WriteProcessMemory_0496 {
  strings:
    $key_0496 = { 53 e4 [2] 61 c6 [2] 67 f3 [2] 49 f3 [2] 76 ef }

  condition:
    any of them
}