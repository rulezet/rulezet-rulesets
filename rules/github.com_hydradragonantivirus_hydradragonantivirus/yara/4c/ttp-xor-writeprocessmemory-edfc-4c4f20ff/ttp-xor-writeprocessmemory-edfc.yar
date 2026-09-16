rule TTP_XOR_WriteProcessMemory_edfc {
  strings:
    $key_edfc = { ba 8e [2] 88 ac [2] 8e 99 [2] a0 99 [2] 9f 85 }

  condition:
    any of them
}