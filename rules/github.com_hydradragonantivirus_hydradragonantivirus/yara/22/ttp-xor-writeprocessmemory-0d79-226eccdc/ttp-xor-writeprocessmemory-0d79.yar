rule TTP_XOR_WriteProcessMemory_0d79 {
  strings:
    $key_0d79 = { 5a 0b [2] 68 29 [2] 6e 1c [2] 40 1c [2] 7f 00 }

  condition:
    any of them
}