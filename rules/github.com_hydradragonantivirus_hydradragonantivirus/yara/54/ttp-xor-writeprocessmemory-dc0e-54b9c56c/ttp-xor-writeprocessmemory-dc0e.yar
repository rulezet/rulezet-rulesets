rule TTP_XOR_WriteProcessMemory_dc0e {
  strings:
    $key_dc0e = { 8b 7c [2] b9 5e [2] bf 6b [2] 91 6b [2] ae 77 }

  condition:
    any of them
}