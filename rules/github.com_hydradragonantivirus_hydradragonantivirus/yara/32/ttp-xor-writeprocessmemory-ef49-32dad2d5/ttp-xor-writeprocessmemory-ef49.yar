rule TTP_XOR_WriteProcessMemory_ef49 {
  strings:
    $key_ef49 = { b8 3b [2] 8a 19 [2] 8c 2c [2] a2 2c [2] 9d 30 }

  condition:
    any of them
}