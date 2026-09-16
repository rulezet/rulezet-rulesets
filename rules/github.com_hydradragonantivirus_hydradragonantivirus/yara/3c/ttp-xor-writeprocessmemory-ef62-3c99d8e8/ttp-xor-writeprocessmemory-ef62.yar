rule TTP_XOR_WriteProcessMemory_ef62 {
  strings:
    $key_ef62 = { b8 10 [2] 8a 32 [2] 8c 07 [2] a2 07 [2] 9d 1b }

  condition:
    any of them
}