rule TTP_XOR_WriteProcessMemory_e806 {
  strings:
    $key_e806 = { bf 74 [2] 8d 56 [2] 8b 63 [2] a5 63 [2] 9a 7f }

  condition:
    any of them
}