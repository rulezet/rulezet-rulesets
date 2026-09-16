rule TTP_XOR_WriteProcessMemory_e827 {
  strings:
    $key_e827 = { bf 55 [2] 8d 77 [2] 8b 42 [2] a5 42 [2] 9a 5e }

  condition:
    any of them
}