rule TTP_XOR_WriteProcessMemory_5151 {
  strings:
    $key_5151 = { 06 23 [2] 34 01 [2] 32 34 [2] 1c 34 [2] 23 28 }

  condition:
    any of them
}