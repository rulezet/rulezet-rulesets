rule TTP_XOR_WriteProcessMemory_117c {
  strings:
    $key_117c = { 46 0e [2] 74 2c [2] 72 19 [2] 5c 19 [2] 63 05 }

  condition:
    any of them
}