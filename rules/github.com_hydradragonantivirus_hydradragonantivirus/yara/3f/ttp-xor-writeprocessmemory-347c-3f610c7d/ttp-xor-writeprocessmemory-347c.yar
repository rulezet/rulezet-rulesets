rule TTP_XOR_WriteProcessMemory_347c {
  strings:
    $key_347c = { 63 0e [2] 51 2c [2] 57 19 [2] 79 19 [2] 46 05 }

  condition:
    any of them
}