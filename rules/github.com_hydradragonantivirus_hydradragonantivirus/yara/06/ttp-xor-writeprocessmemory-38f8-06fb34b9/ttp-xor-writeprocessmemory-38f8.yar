rule TTP_XOR_WriteProcessMemory_38f8 {
  strings:
    $key_38f8 = { 6f 8a [2] 5d a8 [2] 5b 9d [2] 75 9d [2] 4a 81 }

  condition:
    any of them
}