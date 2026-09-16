rule TTP_XOR_WriteProcessMemory_dc2b {
  strings:
    $key_dc2b = { 8b 59 [2] b9 7b [2] bf 4e [2] 91 4e [2] ae 52 }

  condition:
    any of them
}