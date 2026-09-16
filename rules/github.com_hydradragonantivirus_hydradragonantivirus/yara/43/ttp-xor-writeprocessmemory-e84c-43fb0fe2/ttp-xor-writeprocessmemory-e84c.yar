rule TTP_XOR_WriteProcessMemory_e84c {
  strings:
    $key_e84c = { bf 3e [2] 8d 1c [2] 8b 29 [2] a5 29 [2] 9a 35 }

  condition:
    any of them
}