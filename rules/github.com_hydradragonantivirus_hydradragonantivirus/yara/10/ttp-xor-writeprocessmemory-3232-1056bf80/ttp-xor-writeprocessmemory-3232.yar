rule TTP_XOR_WriteProcessMemory_3232 {
  strings:
    $key_3232 = { 65 40 [2] 57 62 [2] 51 57 [2] 7f 57 [2] 40 4b }

  condition:
    any of them
}