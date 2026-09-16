rule TTP_XOR_WriteProcessMemory_6109 {
  strings:
    $key_6109 = { 36 7b [2] 04 59 [2] 02 6c [2] 2c 6c [2] 13 70 }

  condition:
    any of them
}