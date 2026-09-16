rule TTP_XOR_WriteProcessMemory_c601 {
  strings:
    $key_c601 = { 91 73 [2] a3 51 [2] a5 64 [2] 8b 64 [2] b4 78 }

  condition:
    any of them
}