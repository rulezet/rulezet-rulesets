rule TTP_XOR_WriteProcessMemory_c611 {
  strings:
    $key_c611 = { 91 63 [2] a3 41 [2] a5 74 [2] 8b 74 [2] b4 68 }

  condition:
    any of them
}