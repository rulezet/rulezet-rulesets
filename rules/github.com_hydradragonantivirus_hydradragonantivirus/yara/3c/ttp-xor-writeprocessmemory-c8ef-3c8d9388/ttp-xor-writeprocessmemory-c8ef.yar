rule TTP_XOR_WriteProcessMemory_c8ef {
  strings:
    $key_c8ef = { 9f 9d [2] ad bf [2] ab 8a [2] 85 8a [2] ba 96 }

  condition:
    any of them
}