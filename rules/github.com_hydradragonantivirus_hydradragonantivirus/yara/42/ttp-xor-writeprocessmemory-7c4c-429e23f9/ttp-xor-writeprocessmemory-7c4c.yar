rule TTP_XOR_WriteProcessMemory_7c4c {
  strings:
    $key_7c4c = { 2b 3e [2] 19 1c [2] 1f 29 [2] 31 29 [2] 0e 35 }

  condition:
    any of them
}