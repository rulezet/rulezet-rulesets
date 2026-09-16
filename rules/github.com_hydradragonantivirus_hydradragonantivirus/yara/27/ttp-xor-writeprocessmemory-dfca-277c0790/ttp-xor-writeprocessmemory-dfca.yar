rule TTP_XOR_WriteProcessMemory_dfca {
  strings:
    $key_dfca = { 88 b8 [2] ba 9a [2] bc af [2] 92 af [2] ad b3 }

  condition:
    any of them
}