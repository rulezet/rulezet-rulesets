rule TTP_XOR_WriteProcessMemory_e825 {
  strings:
    $key_e825 = { bf 57 [2] 8d 75 [2] 8b 40 [2] a5 40 [2] 9a 5c }

  condition:
    any of them
}