rule TTP_XOR_WriteProcessMemory_3249 {
  strings:
    $key_3249 = { 65 3b [2] 57 19 [2] 51 2c [2] 7f 2c [2] 40 30 }

  condition:
    any of them
}