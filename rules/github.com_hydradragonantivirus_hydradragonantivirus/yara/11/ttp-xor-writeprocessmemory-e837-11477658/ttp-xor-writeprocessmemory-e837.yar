rule TTP_XOR_WriteProcessMemory_e837 {
  strings:
    $key_e837 = { bf 45 [2] 8d 67 [2] 8b 52 [2] a5 52 [2] 9a 4e }

  condition:
    any of them
}