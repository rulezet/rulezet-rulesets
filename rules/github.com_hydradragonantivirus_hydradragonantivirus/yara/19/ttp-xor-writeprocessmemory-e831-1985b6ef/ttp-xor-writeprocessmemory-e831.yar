rule TTP_XOR_WriteProcessMemory_e831 {
  strings:
    $key_e831 = { bf 43 [2] 8d 61 [2] 8b 54 [2] a5 54 [2] 9a 48 }

  condition:
    any of them
}