rule TTP_XOR_WriteProcessMemory_dc05 {
  strings:
    $key_dc05 = { 8b 77 [2] b9 55 [2] bf 60 [2] 91 60 [2] ae 7c }

  condition:
    any of them
}