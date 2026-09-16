rule TTP_XOR_WriteProcessMemory_0038 {
  strings:
    $key_0038 = { 57 4a [2] 65 68 [2] 63 5d [2] 4d 5d [2] 72 41 }

  condition:
    any of them
}