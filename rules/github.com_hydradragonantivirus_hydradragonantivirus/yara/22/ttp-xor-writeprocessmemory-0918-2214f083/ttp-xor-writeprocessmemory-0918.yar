rule TTP_XOR_WriteProcessMemory_0918 {
  strings:
    $key_0918 = { 5e 6a [2] 6c 48 [2] 6a 7d [2] 44 7d [2] 7b 61 }

  condition:
    any of them
}