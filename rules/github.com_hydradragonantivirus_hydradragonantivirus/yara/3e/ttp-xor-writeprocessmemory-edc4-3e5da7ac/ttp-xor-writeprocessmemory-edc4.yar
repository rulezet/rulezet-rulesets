rule TTP_XOR_WriteProcessMemory_edc4 {
  strings:
    $key_edc4 = { ba b6 [2] 88 94 [2] 8e a1 [2] a0 a1 [2] 9f bd }

  condition:
    any of them
}