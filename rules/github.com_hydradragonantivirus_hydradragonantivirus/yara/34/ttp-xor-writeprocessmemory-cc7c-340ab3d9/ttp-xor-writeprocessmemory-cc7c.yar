rule TTP_XOR_WriteProcessMemory_cc7c {
  strings:
    $key_cc7c = { 9b 0e [2] a9 2c [2] af 19 [2] 81 19 [2] be 05 }

  condition:
    any of them
}