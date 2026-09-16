rule TTP_XOR_WriteProcessMemory_615e {
  strings:
    $key_615e = { 36 2c [2] 04 0e [2] 02 3b [2] 2c 3b [2] 13 27 }

  condition:
    any of them
}