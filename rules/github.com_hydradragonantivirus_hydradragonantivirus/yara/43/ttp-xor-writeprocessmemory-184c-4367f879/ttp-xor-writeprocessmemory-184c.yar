rule TTP_XOR_WriteProcessMemory_184c {
  strings:
    $key_184c = { 4f 3e [2] 7d 1c [2] 7b 29 [2] 55 29 [2] 6a 35 }

  condition:
    any of them
}