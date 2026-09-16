rule TTP_XOR_WriteProcessMemory_eb18 {
  strings:
    $key_eb18 = { bc 6a [2] 8e 48 [2] 88 7d [2] a6 7d [2] 99 61 }

  condition:
    any of them
}