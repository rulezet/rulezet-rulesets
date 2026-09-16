rule TTP_XOR_WriteProcessMemory_c818 {
  strings:
    $key_c818 = { 9f 6a [2] ad 48 [2] ab 7d [2] 85 7d [2] ba 61 }

  condition:
    any of them
}