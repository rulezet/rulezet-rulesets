rule TTP_XOR_WriteProcessMemory_edc1 {
  strings:
    $key_edc1 = { ba b3 [2] 88 91 [2] 8e a4 [2] a0 a4 [2] 9f b8 }

  condition:
    any of them
}