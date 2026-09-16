rule TTP_XOR_WriteProcessMemory_f8fc {
  strings:
    $key_f8fc = { af 8e [2] 9d ac [2] 9b 99 [2] b5 99 [2] 8a 85 }

  condition:
    any of them
}