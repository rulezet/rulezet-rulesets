rule TTP_XOR_WriteProcessMemory_c604 {
  strings:
    $key_c604 = { 91 76 [2] a3 54 [2] a5 61 [2] 8b 61 [2] b4 7d }

  condition:
    any of them
}