rule TTP_XOR_WriteProcessMemory_6ce8 {
  strings:
    $key_6ce8 = { 3b 9a [2] 09 b8 [2] 0f 8d [2] 21 8d [2] 1e 91 }

  condition:
    any of them
}