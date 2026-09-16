rule TTP_XOR_WriteProcessMemory_ef20 {
  strings:
    $key_ef20 = { b8 52 [2] 8a 70 [2] 8c 45 [2] a2 45 [2] 9d 59 }

  condition:
    any of them
}