rule TTP_XOR_WriteProcessMemory_2111 {
  strings:
    $key_2111 = { 76 63 [2] 44 41 [2] 42 74 [2] 6c 74 [2] 53 68 }

  condition:
    any of them
}