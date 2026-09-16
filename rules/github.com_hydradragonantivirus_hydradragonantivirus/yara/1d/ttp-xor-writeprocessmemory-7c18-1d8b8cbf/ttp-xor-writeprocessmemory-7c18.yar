rule TTP_XOR_WriteProcessMemory_7c18 {
  strings:
    $key_7c18 = { 2b 6a [2] 19 48 [2] 1f 7d [2] 31 7d [2] 0e 61 }

  condition:
    any of them
}