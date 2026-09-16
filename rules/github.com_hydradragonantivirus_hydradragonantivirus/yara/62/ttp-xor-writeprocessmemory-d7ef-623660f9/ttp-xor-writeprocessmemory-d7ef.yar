rule TTP_XOR_WriteProcessMemory_d7ef {
  strings:
    $key_d7ef = { 80 9d [2] b2 bf [2] b4 8a [2] 9a 8a [2] a5 96 }

  condition:
    any of them
}