rule TTP_XOR_WriteProcessMemory_eb79 {
  strings:
    $key_eb79 = { bc 0b [2] 8e 29 [2] 88 1c [2] a6 1c [2] 99 00 }

  condition:
    any of them
}