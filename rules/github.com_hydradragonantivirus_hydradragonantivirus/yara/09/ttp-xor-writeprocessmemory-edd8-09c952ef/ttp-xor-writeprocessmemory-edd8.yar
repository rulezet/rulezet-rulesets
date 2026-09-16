rule TTP_XOR_WriteProcessMemory_edd8 {
  strings:
    $key_edd8 = { ba aa [2] 88 88 [2] 8e bd [2] a0 bd [2] 9f a1 }

  condition:
    any of them
}