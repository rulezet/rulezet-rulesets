rule TTP_XOR_WriteProcessMemory_6c4c {
  strings:
    $key_6c4c = { 3b 3e [2] 09 1c [2] 0f 29 [2] 21 29 [2] 1e 35 }

  condition:
    any of them
}