rule TTP_XOR_WriteProcessMemory_e879 {
  strings:
    $key_e879 = { bf 0b [2] 8d 29 [2] 8b 1c [2] a5 1c [2] 9a 00 }

  condition:
    any of them
}