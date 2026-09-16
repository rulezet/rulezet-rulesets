rule TTP_XOR_WriteProcessMemory_fa8f {
  strings:
    $key_fa8f = { ad fd [2] 9f df [2] 99 ea [2] b7 ea [2] 88 f6 }

  condition:
    any of them
}