rule TTP_XOR_WriteProcessMemory_f83c {
  strings:
    $key_f83c = { af 4e [2] 9d 6c [2] 9b 59 [2] b5 59 [2] 8a 45 }

  condition:
    any of them
}