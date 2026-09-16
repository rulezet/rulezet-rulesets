rule TTP_XOR_WriteProcessMemory_0228 {
  strings:
    $key_0228 = { 55 5a [2] 67 78 [2] 61 4d [2] 4f 4d [2] 70 51 }

  condition:
    any of them
}