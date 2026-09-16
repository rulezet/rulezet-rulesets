rule TTP_XOR_WriteProcessMemory_f84e {
  strings:
    $key_f84e = { af 3c [2] 9d 1e [2] 9b 2b [2] b5 2b [2] 8a 37 }

  condition:
    any of them
}