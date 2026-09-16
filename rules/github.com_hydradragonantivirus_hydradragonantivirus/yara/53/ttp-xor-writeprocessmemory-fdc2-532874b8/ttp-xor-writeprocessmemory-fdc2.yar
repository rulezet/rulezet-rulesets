rule TTP_XOR_WriteProcessMemory_fdc2 {
  strings:
    $key_fdc2 = { aa b0 [2] 98 92 [2] 9e a7 [2] b0 a7 [2] 8f bb }

  condition:
    any of them
}