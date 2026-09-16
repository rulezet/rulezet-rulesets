rule TTP_XOR_WriteProcessMemory_eb92 {
  strings:
    $key_eb92 = { bc e0 [2] 8e c2 [2] 88 f7 [2] a6 f7 [2] 99 eb }

  condition:
    any of them
}