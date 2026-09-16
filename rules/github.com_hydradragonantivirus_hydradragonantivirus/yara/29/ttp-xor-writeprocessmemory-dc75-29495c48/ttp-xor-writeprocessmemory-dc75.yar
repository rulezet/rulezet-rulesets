rule TTP_XOR_WriteProcessMemory_dc75 {
  strings:
    $key_dc75 = { 8b 07 [2] b9 25 [2] bf 10 [2] 91 10 [2] ae 0c }

  condition:
    any of them
}