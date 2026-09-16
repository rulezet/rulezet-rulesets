rule TTP_XOR_WriteProcessMemory_e857 {
  strings:
    $key_e857 = { bf 25 [2] 8d 07 [2] 8b 32 [2] a5 32 [2] 9a 2e }

  condition:
    any of them
}