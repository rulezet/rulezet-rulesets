rule TTP_XOR_WriteProcessMemory_620c {
  strings:
    $key_620c = { 35 7e [2] 07 5c [2] 01 69 [2] 2f 69 [2] 10 75 }

  condition:
    any of them
}