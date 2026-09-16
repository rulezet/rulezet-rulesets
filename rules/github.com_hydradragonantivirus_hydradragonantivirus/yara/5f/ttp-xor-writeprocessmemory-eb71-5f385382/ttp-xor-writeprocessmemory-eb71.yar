rule TTP_XOR_WriteProcessMemory_eb71 {
  strings:
    $key_eb71 = { bc 03 [2] 8e 21 [2] 88 14 [2] a6 14 [2] 99 08 }

  condition:
    any of them
}