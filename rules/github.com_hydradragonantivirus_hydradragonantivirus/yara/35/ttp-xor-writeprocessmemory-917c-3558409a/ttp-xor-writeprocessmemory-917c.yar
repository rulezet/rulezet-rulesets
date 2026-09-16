rule TTP_XOR_WriteProcessMemory_917c {
  strings:
    $key_917c = { c6 0e [2] f4 2c [2] f2 19 [2] dc 19 [2] e3 05 }

  condition:
    any of them
}