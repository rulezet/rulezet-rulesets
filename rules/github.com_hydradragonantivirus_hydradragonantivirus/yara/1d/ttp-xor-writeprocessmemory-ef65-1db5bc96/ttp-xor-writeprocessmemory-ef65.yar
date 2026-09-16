rule TTP_XOR_WriteProcessMemory_ef65 {
  strings:
    $key_ef65 = { b8 17 [2] 8a 35 [2] 8c 00 [2] a2 00 [2] 9d 1c }

  condition:
    any of them
}