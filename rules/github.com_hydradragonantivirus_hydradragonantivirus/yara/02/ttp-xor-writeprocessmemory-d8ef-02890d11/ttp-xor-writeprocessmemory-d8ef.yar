rule TTP_XOR_WriteProcessMemory_d8ef {
  strings:
    $key_d8ef = { 8f 9d [2] bd bf [2] bb 8a [2] 95 8a [2] aa 96 }

  condition:
    any of them
}