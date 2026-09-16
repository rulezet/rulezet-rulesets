rule TTP_XOR_WriteProcessMemory_e804 {
  strings:
    $key_e804 = { bf 76 [2] 8d 54 [2] 8b 61 [2] a5 61 [2] 9a 7d }

  condition:
    any of them
}