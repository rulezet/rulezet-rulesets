rule TTP_XOR_WriteProcessMemory_5c18 {
  strings:
    $key_5c18 = { 0b 6a [2] 39 48 [2] 3f 7d [2] 11 7d [2] 2e 61 }

  condition:
    any of them
}