rule TTP_XOR_WriteProcessMemory_4b38 {
  strings:
    $key_4b38 = { 1c 4a [2] 2e 68 [2] 28 5d [2] 06 5d [2] 39 41 }

  condition:
    any of them
}