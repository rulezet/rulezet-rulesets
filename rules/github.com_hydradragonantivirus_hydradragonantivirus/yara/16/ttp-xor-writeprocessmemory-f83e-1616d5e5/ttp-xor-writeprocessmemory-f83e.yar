rule TTP_XOR_WriteProcessMemory_f83e {
  strings:
    $key_f83e = { af 4c [2] 9d 6e [2] 9b 5b [2] b5 5b [2] 8a 47 }

  condition:
    any of them
}