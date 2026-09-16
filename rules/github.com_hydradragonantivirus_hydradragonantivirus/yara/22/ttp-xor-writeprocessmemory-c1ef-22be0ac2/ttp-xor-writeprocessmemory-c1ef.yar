rule TTP_XOR_WriteProcessMemory_c1ef {
  strings:
    $key_c1ef = { 96 9d [2] a4 bf [2] a2 8a [2] 8c 8a [2] b3 96 }

  condition:
    any of them
}