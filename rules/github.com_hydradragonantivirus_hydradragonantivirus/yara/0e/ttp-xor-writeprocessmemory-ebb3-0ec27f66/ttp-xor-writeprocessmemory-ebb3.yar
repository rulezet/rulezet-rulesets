rule TTP_XOR_WriteProcessMemory_ebb3 {
  strings:
    $key_ebb3 = { bc c1 [2] 8e e3 [2] 88 d6 [2] a6 d6 [2] 99 ca }

  condition:
    any of them
}