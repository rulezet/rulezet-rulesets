rule TTP_XOR_WriteProcessMemory_d0ef {
  strings:
    $key_d0ef = { 87 9d [2] b5 bf [2] b3 8a [2] 9d 8a [2] a2 96 }

  condition:
    any of them
}