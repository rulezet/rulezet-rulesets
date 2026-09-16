rule TTP_XOR_WriteProcessMemory_f86c {
  strings:
    $key_f86c = { af 1e [2] 9d 3c [2] 9b 09 [2] b5 09 [2] 8a 15 }

  condition:
    any of them
}