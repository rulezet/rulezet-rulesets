rule TTP_XOR_WriteProcessMemory_f87e {
  strings:
    $key_f87e = { af 0c [2] 9d 2e [2] 9b 1b [2] b5 1b [2] 8a 07 }

  condition:
    any of them
}