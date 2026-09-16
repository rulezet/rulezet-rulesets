rule TTP_XOR_WriteProcessMemory_e835 {
  strings:
    $key_e835 = { bf 47 [2] 8d 65 [2] 8b 50 [2] a5 50 [2] 9a 4c }

  condition:
    any of them
}