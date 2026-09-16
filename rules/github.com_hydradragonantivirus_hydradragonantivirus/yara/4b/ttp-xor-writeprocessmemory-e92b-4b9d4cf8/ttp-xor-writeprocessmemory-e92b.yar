rule TTP_XOR_WriteProcessMemory_e92b {
  strings:
    $key_e92b = { be 59 [2] 8c 7b [2] 8a 4e [2] a4 4e [2] 9b 52 }

  condition:
    any of them
}