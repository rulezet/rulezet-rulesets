rule TTP_XOR_WriteProcessMemory_f57c {
  strings:
    $key_f57c = { a2 0e [2] 90 2c [2] 96 19 [2] b8 19 [2] 87 05 }

  condition:
    any of them
}