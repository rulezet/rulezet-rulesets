rule TTP_XOR_WriteProcessMemory_4c79 {
  strings:
    $key_4c79 = { 1b 0b [2] 29 29 [2] 2f 1c [2] 01 1c [2] 3e 00 }

  condition:
    any of them
}