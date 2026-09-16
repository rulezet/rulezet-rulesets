rule TTP_XOR_WriteProcessMemory_e813 {
  strings:
    $key_e813 = { bf 61 [2] 8d 43 [2] 8b 76 [2] a5 76 [2] 9a 6a }

  condition:
    any of them
}