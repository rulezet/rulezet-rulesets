rule TTP_XOR_WriteProcessMemory_3278 {
  strings:
    $key_3278 = { 65 0a [2] 57 28 [2] 51 1d [2] 7f 1d [2] 40 01 }

  condition:
    any of them
}