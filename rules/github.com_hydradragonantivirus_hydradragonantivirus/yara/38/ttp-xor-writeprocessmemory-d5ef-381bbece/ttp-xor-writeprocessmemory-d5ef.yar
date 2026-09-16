rule TTP_XOR_WriteProcessMemory_d5ef {
  strings:
    $key_d5ef = { 82 9d [2] b0 bf [2] b6 8a [2] 98 8a [2] a7 96 }

  condition:
    any of them
}