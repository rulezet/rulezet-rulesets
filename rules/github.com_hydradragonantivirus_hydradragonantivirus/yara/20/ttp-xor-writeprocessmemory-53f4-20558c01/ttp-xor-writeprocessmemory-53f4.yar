rule TTP_XOR_WriteProcessMemory_53f4 {
  strings:
    $key_53f4 = { 04 86 [2] 36 a4 [2] 30 91 [2] 1e 91 [2] 21 8d }

  condition:
    any of them
}