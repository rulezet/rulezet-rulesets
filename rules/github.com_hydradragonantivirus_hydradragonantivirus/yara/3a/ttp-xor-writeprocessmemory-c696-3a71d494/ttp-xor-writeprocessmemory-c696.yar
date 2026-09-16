rule TTP_XOR_WriteProcessMemory_c696 {
  strings:
    $key_c696 = { 91 e4 [2] a3 c6 [2] a5 f3 [2] 8b f3 [2] b4 ef }

  condition:
    any of them
}