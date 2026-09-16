rule TTP_XOR_WriteProcessMemory_037c {
  strings:
    $key_037c = { 54 0e [2] 66 2c [2] 60 19 [2] 4e 19 [2] 71 05 }

  condition:
    any of them
}