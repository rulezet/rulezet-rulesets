rule TTP_XOR_WriteProcessMemory_edc8 {
  strings:
    $key_edc8 = { ba ba [2] 88 98 [2] 8e ad [2] a0 ad [2] 9f b1 }

  condition:
    any of them
}