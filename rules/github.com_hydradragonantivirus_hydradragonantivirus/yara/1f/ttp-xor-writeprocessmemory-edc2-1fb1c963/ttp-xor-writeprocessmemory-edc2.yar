rule TTP_XOR_WriteProcessMemory_edc2 {
  strings:
    $key_edc2 = { ba b0 [2] 88 92 [2] 8e a7 [2] a0 a7 [2] 9f bb }

  condition:
    any of them
}