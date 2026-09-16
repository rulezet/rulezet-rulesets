rule TTP_XOR_WriteProcessMemory_e817 {
  strings:
    $key_e817 = { bf 65 [2] 8d 47 [2] 8b 72 [2] a5 72 [2] 9a 6e }

  condition:
    any of them
}