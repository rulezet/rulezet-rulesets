rule TTP_XOR_WriteProcessMemory_5ce8 {
  strings:
    $key_5ce8 = { 0b 9a [2] 39 b8 [2] 3f 8d [2] 11 8d [2] 2e 91 }

  condition:
    any of them
}