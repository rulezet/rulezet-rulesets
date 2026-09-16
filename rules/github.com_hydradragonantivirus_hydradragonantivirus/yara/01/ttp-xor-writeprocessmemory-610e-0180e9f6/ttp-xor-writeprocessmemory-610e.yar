rule TTP_XOR_WriteProcessMemory_610e {
  strings:
    $key_610e = { 36 7c [2] 04 5e [2] 02 6b [2] 2c 6b [2] 13 77 }

  condition:
    any of them
}