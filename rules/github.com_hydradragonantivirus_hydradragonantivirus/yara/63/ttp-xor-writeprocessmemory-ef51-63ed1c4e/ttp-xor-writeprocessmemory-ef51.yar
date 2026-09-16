rule TTP_XOR_WriteProcessMemory_ef51 {
  strings:
    $key_ef51 = { b8 23 [2] 8a 01 [2] 8c 34 [2] a2 34 [2] 9d 28 }

  condition:
    any of them
}