rule TTP_XOR_WriteProcessMemory_b679 {
  strings:
    $key_b679 = { e1 0b [2] d3 29 [2] d5 1c [2] fb 1c [2] c4 00 }

  condition:
    any of them
}