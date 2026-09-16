rule TTP_XOR_WriteProcessMemory_7ce8 {
  strings:
    $key_7ce8 = { 2b 9a [2] 19 b8 [2] 1f 8d [2] 31 8d [2] 0e 91 }

  condition:
    any of them
}