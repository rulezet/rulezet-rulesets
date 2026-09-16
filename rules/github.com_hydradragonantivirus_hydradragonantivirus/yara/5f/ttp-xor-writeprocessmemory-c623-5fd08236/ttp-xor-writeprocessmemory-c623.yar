rule TTP_XOR_WriteProcessMemory_c623 {
  strings:
    $key_c623 = { 91 51 [2] a3 73 [2] a5 46 [2] 8b 46 [2] b4 5a }

  condition:
    any of them
}