rule TTP_XOR_WriteProcessMemory_f83b {
  strings:
    $key_f83b = { af 49 [2] 9d 6b [2] 9b 5e [2] b5 5e [2] 8a 42 }

  condition:
    any of them
}