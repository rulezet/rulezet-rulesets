rule TTP_XOR_WriteProcessMemory_3670 {
  strings:
    $key_3670 = { 61 02 [2] 53 20 [2] 55 15 [2] 7b 15 [2] 44 09 }

  condition:
    any of them
}