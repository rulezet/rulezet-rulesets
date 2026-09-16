rule TTP_XOR_WriteProcessMemory_e92c {
  strings:
    $key_e92c = { be 5e [2] 8c 7c [2] 8a 49 [2] a4 49 [2] 9b 55 }

  condition:
    any of them
}