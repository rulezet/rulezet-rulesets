rule TTP_XOR_WriteProcessMemory_dc6c {
  strings:
    $key_dc6c = { 8b 1e [2] b9 3c [2] bf 09 [2] 91 09 [2] ae 15 }

  condition:
    any of them
}