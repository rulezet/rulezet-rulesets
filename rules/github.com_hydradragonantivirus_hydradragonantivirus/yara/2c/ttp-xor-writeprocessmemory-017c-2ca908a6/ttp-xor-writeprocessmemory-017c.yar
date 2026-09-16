rule TTP_XOR_WriteProcessMemory_017c {
  strings:
    $key_017c = { 56 0e [2] 64 2c [2] 62 19 [2] 4c 19 [2] 73 05 }

  condition:
    any of them
}