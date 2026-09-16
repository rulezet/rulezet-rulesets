rule TTP_XOR_WriteProcessMemory_3c18 {
  strings:
    $key_3c18 = { 6b 6a [2] 59 48 [2] 5f 7d [2] 71 7d [2] 4e 61 }

  condition:
    any of them
}