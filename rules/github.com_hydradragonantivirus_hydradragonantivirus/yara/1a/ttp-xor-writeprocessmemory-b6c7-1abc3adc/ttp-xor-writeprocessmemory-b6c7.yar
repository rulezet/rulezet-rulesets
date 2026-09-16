rule TTP_XOR_WriteProcessMemory_b6c7 {
  strings:
    $key_b6c7 = { e1 b5 [2] d3 97 [2] d5 a2 [2] fb a2 [2] c4 be }

  condition:
    any of them
}