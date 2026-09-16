rule TTP_XOR_WriteProcessMemory_e854 {
  strings:
    $key_e854 = { bf 26 [2] 8d 04 [2] 8b 31 [2] a5 31 [2] 9a 2d }

  condition:
    any of them
}