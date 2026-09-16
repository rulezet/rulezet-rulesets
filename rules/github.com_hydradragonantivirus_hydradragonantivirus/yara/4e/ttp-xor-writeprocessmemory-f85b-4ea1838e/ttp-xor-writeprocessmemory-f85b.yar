rule TTP_XOR_WriteProcessMemory_f85b {
  strings:
    $key_f85b = { af 29 [2] 9d 0b [2] 9b 3e [2] b5 3e [2] 8a 22 }

  condition:
    any of them
}