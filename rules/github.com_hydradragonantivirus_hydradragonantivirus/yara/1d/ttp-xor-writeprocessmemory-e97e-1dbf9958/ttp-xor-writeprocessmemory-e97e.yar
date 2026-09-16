rule TTP_XOR_WriteProcessMemory_e97e {
  strings:
    $key_e97e = { be 0c [2] 8c 2e [2] 8a 1b [2] a4 1b [2] 9b 07 }

  condition:
    any of them
}