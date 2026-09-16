rule TTP_XOR_WriteProcessMemory_edce {
  strings:
    $key_edce = { ba bc [2] 88 9e [2] 8e ab [2] a0 ab [2] 9f b7 }

  condition:
    any of them
}