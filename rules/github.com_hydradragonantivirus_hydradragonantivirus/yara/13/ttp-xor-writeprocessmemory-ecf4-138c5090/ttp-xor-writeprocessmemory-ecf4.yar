rule TTP_XOR_WriteProcessMemory_ecf4 {
  strings:
    $key_ecf4 = { bb 86 [2] 89 a4 [2] 8f 91 [2] a1 91 [2] 9e 8d }

  condition:
    any of them
}