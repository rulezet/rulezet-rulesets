rule TTP_XOR_WriteProcessMemory_5cf4 {
  strings:
    $key_5cf4 = { 0b 86 [2] 39 a4 [2] 3f 91 [2] 11 91 [2] 2e 8d }

  condition:
    any of them
}