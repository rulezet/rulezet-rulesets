rule TTP_XOR_WriteProcessMemory_cbda {
  strings:
    $key_cbda = { 9c a8 [2] ae 8a [2] a8 bf [2] 86 bf [2] b9 a3 }

  condition:
    any of them
}