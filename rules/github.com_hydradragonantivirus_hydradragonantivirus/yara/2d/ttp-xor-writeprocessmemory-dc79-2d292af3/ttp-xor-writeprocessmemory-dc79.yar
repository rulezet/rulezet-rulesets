rule TTP_XOR_WriteProcessMemory_dc79 {
  strings:
    $key_dc79 = { 8b 0b [2] b9 29 [2] bf 1c [2] 91 1c [2] ae 00 }

  condition:
    any of them
}