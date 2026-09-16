rule TTP_XOR_WriteProcessMemory_dc2e {
  strings:
    $key_dc2e = { 8b 5c [2] b9 7e [2] bf 4b [2] 91 4b [2] ae 57 }

  condition:
    any of them
}