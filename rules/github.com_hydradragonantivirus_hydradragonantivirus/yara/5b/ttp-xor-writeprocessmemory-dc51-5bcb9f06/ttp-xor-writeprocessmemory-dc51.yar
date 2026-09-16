rule TTP_XOR_WriteProcessMemory_dc51 {
  strings:
    $key_dc51 = { 8b 23 [2] b9 01 [2] bf 34 [2] 91 34 [2] ae 28 }

  condition:
    any of them
}