rule TTP_XOR_WriteProcessMemory_edf4 {
  strings:
    $key_edf4 = { ba 86 [2] 88 a4 [2] 8e 91 [2] a0 91 [2] 9f 8d }

  condition:
    any of them
}