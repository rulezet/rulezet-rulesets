rule TTP_XOR_WriteProcessMemory_eb10 {
  strings:
    $key_eb10 = { bc 62 [2] 8e 40 [2] 88 75 [2] a6 75 [2] 99 69 }

  condition:
    any of them
}