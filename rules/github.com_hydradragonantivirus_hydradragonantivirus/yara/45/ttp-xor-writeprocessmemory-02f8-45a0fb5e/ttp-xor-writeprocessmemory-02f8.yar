rule TTP_XOR_WriteProcessMemory_02f8 {
  strings:
    $key_02f8 = { 55 8a [2] 67 a8 [2] 61 9d [2] 4f 9d [2] 70 81 }

  condition:
    any of them
}