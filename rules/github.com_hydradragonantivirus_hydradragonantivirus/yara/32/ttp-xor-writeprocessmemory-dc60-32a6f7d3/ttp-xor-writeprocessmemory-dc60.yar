rule TTP_XOR_WriteProcessMemory_dc60 {
  strings:
    $key_dc60 = { 8b 12 [2] b9 30 [2] bf 05 [2] 91 05 [2] ae 19 }

  condition:
    any of them
}