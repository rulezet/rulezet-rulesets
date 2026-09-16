rule TTP_XOR_WriteProcessMemory_f82b {
  strings:
    $key_f82b = { af 59 [2] 9d 7b [2] 9b 4e [2] b5 4e [2] 8a 52 }

  condition:
    any of them
}