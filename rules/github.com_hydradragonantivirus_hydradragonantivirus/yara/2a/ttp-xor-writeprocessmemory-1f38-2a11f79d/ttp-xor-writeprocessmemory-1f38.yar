rule TTP_XOR_WriteProcessMemory_1f38 {
  strings:
    $key_1f38 = { 48 4a [2] 7a 68 [2] 7c 5d [2] 52 5d [2] 6d 41 }

  condition:
    any of them
}