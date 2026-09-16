rule TTP_XOR_WriteProcessMemory_e83d {
  strings:
    $key_e83d = { bf 4f [2] 8d 6d [2] 8b 58 [2] a5 58 [2] 9a 44 }

  condition:
    any of them
}