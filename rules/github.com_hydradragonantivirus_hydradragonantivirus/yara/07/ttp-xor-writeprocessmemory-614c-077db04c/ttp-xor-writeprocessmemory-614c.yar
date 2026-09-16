rule TTP_XOR_WriteProcessMemory_614c {
  strings:
    $key_614c = { 36 3e [2] 04 1c [2] 02 29 [2] 2c 29 [2] 13 35 }

  condition:
    any of them
}