rule TTP_XOR_WriteProcessMemory_e824 {
  strings:
    $key_e824 = { bf 56 [2] 8d 74 [2] 8b 41 [2] a5 41 [2] 9a 5d }

  condition:
    any of them
}