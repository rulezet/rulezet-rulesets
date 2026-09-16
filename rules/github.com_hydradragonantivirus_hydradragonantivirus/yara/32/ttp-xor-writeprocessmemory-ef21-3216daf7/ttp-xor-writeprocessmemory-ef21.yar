rule TTP_XOR_WriteProcessMemory_ef21 {
  strings:
    $key_ef21 = { b8 53 [2] 8a 71 [2] 8c 44 [2] a2 44 [2] 9d 58 }

  condition:
    any of them
}