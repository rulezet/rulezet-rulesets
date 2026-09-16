rule TTP_XOR_WriteProcessMemory_e511 {
  strings:
    $key_e511 = { b2 63 [2] 80 41 [2] 86 74 [2] a8 74 [2] 97 68 }

  condition:
    any of them
}