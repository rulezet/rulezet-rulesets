rule TTP_XOR_WriteProcessMemory_c660 {
  strings:
    $key_c660 = { 91 12 [2] a3 30 [2] a5 05 [2] 8b 05 [2] b4 19 }

  condition:
    any of them
}