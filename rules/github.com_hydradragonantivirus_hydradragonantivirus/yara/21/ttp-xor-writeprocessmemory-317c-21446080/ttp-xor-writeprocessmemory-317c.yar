rule TTP_XOR_WriteProcessMemory_317c {
  strings:
    $key_317c = { 66 0e [2] 54 2c [2] 52 19 [2] 7c 19 [2] 43 05 }

  condition:
    any of them
}