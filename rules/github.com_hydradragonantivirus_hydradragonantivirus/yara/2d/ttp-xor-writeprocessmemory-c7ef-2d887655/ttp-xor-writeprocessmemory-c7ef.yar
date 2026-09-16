rule TTP_XOR_WriteProcessMemory_c7ef {
  strings:
    $key_c7ef = { 90 9d [2] a2 bf [2] a4 8a [2] 8a 8a [2] b5 96 }

  condition:
    any of them
}