rule TTP_XOR_WriteProcessMemory_f81e {
  strings:
    $key_f81e = { af 6c [2] 9d 4e [2] 9b 7b [2] b5 7b [2] 8a 67 }

  condition:
    any of them
}