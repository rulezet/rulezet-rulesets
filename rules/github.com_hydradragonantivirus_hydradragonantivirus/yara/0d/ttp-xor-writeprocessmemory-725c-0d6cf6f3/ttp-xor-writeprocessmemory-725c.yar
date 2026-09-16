rule TTP_XOR_WriteProcessMemory_725c {
  strings:
    $key_725c = { 25 2e [2] 17 0c [2] 11 39 [2] 3f 39 [2] 00 25 }

  condition:
    any of them
}