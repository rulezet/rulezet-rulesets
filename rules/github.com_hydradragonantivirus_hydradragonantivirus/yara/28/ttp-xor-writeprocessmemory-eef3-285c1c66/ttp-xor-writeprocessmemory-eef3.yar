rule TTP_XOR_WriteProcessMemory_eef3 {
  strings:
    $key_eef3 = { b9 81 [2] 8b a3 [2] 8d 96 [2] a3 96 [2] 9c 8a }

  condition:
    any of them
}