rule TTP_XOR_WriteProcessMemory_c7da {
  strings:
    $key_c7da = { 90 a8 [2] a2 8a [2] a4 bf [2] 8a bf [2] b5 a3 }

  condition:
    any of them
}