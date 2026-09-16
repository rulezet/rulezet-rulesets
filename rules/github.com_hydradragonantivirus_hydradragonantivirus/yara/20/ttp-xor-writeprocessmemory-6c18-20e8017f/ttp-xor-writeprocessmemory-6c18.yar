rule TTP_XOR_WriteProcessMemory_6c18 {
  strings:
    $key_6c18 = { 3b 6a [2] 09 48 [2] 0f 7d [2] 21 7d [2] 1e 61 }

  condition:
    any of them
}