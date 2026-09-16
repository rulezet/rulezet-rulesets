rule TTP_XOR_WriteProcessMemory_f8cd {
  strings:
    $key_f8cd = { af bf [2] 9d 9d [2] 9b a8 [2] b5 a8 [2] 8a b4 }

  condition:
    any of them
}