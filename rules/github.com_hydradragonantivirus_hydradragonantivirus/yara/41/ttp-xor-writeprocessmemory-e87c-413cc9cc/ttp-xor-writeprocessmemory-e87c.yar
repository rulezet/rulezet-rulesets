rule TTP_XOR_WriteProcessMemory_e87c {
  strings:
    $key_e87c = { bf 0e [2] 8d 2c [2] 8b 19 [2] a5 19 [2] 9a 05 }

  condition:
    any of them
}