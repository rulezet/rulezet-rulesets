rule TTP_XOR_WriteProcessMemory_b671 {
  strings:
    $key_b671 = { e1 03 [2] d3 21 [2] d5 14 [2] fb 14 [2] c4 08 }

  condition:
    any of them
}