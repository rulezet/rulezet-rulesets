rule TTP_XOR_WriteProcessMemory_4b28 {
  strings:
    $key_4b28 = { 1c 5a [2] 2e 78 [2] 28 4d [2] 06 4d [2] 39 51 }

  condition:
    any of them
}