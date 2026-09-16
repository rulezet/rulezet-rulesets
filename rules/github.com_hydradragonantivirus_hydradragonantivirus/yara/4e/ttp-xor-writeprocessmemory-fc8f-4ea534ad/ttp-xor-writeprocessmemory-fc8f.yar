rule TTP_XOR_WriteProcessMemory_fc8f {
  strings:
    $key_fc8f = { ab fd [2] 99 df [2] 9f ea [2] b1 ea [2] 8e f6 }

  condition:
    any of them
}