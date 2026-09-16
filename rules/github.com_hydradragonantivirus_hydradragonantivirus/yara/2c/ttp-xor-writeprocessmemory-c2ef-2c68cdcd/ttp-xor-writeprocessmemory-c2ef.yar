rule TTP_XOR_WriteProcessMemory_c2ef {
  strings:
    $key_c2ef = { 95 9d [2] a7 bf [2] a1 8a [2] 8f 8a [2] b0 96 }

  condition:
    any of them
}