rule TTP_XOR_WriteProcessMemory_7128 {
  strings:
    $key_7128 = { 26 5a [2] 14 78 [2] 12 4d [2] 3c 4d [2] 03 51 }

  condition:
    any of them
}