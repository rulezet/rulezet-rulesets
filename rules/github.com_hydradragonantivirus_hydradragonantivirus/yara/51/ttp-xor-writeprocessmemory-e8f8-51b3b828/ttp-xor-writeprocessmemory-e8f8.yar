rule TTP_XOR_WriteProcessMemory_e8f8 {
  strings:
    $key_e8f8 = { bf 8a [2] 8d a8 [2] 8b 9d [2] a5 9d [2] 9a 81 }

  condition:
    any of them
}