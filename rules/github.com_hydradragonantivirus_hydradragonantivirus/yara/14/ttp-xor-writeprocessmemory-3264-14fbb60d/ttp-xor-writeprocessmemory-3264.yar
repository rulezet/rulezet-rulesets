rule TTP_XOR_WriteProcessMemory_3264 {
  strings:
    $key_3264 = { 65 16 [2] 57 34 [2] 51 01 [2] 7f 01 [2] 40 1d }

  condition:
    any of them
}