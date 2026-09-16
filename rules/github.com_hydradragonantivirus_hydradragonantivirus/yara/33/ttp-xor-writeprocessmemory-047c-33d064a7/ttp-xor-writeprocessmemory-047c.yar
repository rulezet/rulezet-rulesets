rule TTP_XOR_WriteProcessMemory_047c {
  strings:
    $key_047c = { 53 0e [2] 61 2c [2] 67 19 [2] 49 19 [2] 76 05 }

  condition:
    any of them
}