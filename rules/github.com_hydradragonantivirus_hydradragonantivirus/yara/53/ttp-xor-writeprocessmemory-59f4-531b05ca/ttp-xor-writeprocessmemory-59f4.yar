rule TTP_XOR_WriteProcessMemory_59f4 {
  strings:
    $key_59f4 = { 0e 86 [2] 3c a4 [2] 3a 91 [2] 14 91 [2] 2b 8d }

  condition:
    any of them
}