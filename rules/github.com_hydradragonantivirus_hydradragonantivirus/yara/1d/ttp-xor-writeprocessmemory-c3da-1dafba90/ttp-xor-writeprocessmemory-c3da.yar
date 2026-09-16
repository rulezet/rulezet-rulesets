rule TTP_XOR_WriteProcessMemory_c3da {
  strings:
    $key_c3da = { 94 a8 [2] a6 8a [2] a0 bf [2] 8e bf [2] b1 a3 }

  condition:
    any of them
}