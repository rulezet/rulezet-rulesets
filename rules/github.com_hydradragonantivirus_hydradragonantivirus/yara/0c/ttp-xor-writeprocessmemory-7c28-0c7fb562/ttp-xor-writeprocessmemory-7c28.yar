rule TTP_XOR_WriteProcessMemory_7c28 {
  strings:
    $key_7c28 = { 2b 5a [2] 19 78 [2] 1f 4d [2] 31 4d [2] 0e 51 }

  condition:
    any of them
}