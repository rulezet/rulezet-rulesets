rule TTP_XOR_WriteProcessMemory_c697 {
  strings:
    $key_c697 = { 91 e5 [2] a3 c7 [2] a5 f2 [2] 8b f2 [2] b4 ee }

  condition:
    any of them
}