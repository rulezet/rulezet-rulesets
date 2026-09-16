rule TTP_XOR_WriteProcessMemory_e8e3 {
  strings:
    $key_e8e3 = { bf 91 [2] 8d b3 [2] 8b 86 [2] a5 86 [2] 9a 9a }

  condition:
    any of them
}