rule TTP_XOR_WriteProcessMemory_eba3 {
  strings:
    $key_eba3 = { bc d1 [2] 8e f3 [2] 88 c6 [2] a6 c6 [2] 99 da }

  condition:
    any of them
}