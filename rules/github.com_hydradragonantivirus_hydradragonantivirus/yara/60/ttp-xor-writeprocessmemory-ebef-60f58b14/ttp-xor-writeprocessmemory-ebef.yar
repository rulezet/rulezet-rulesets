rule TTP_XOR_WriteProcessMemory_ebef {
  strings:
    $key_ebef = { bc 9d [2] 8e bf [2] 88 8a [2] a6 8a [2] 99 96 }

  condition:
    any of them
}