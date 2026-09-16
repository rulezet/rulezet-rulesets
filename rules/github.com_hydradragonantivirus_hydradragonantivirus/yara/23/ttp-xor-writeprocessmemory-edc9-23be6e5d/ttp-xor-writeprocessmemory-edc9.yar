rule TTP_XOR_WriteProcessMemory_edc9 {
  strings:
    $key_edc9 = { ba bb [2] 88 99 [2] 8e ac [2] a0 ac [2] 9f b0 }

  condition:
    any of them
}