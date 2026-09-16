rule TTP_XOR_WriteProcessMemory_2770 {
  strings:
    $key_2770 = { 70 02 [2] 42 20 [2] 44 15 [2] 6a 15 [2] 55 09 }

  condition:
    any of them
}