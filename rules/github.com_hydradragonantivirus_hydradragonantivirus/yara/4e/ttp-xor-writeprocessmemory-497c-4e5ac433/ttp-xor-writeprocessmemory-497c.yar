rule TTP_XOR_WriteProcessMemory_497c {
  strings:
    $key_497c = { 1e 0e [2] 2c 2c [2] 2a 19 [2] 04 19 [2] 3b 05 }

  condition:
    any of them
}