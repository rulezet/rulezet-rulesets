rule TTP_XOR_WriteProcessMemory_dc6e {
  strings:
    $key_dc6e = { 8b 1c [2] b9 3e [2] bf 0b [2] 91 0b [2] ae 17 }

  condition:
    any of them
}