rule TTP_XOR_WriteProcessMemory_e834 {
  strings:
    $key_e834 = { bf 46 [2] 8d 64 [2] 8b 51 [2] a5 51 [2] 9a 4d }

  condition:
    any of them
}