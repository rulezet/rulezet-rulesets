rule TTP_XOR_WriteProcessMemory_e92e {
  strings:
    $key_e92e = { be 5c [2] 8c 7e [2] 8a 4b [2] a4 4b [2] 9b 57 }

  condition:
    any of them
}