rule TTP_XOR_WriteProcessMemory_e844 {
  strings:
    $key_e844 = { bf 36 [2] 8d 14 [2] 8b 21 [2] a5 21 [2] 9a 3d }

  condition:
    any of them
}