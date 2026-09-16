rule TTP_XOR_WriteProcessMemory_7a2c {
  strings:
    $key_7a2c = { 2d 5e [2] 1f 7c [2] 19 49 [2] 37 49 [2] 08 55 }

  condition:
    any of them
}