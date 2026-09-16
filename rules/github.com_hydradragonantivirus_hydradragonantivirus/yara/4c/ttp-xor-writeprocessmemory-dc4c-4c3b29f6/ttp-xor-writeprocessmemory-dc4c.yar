rule TTP_XOR_WriteProcessMemory_dc4c {
  strings:
    $key_dc4c = { 8b 3e [2] b9 1c [2] bf 29 [2] 91 29 [2] ae 35 }

  condition:
    any of them
}