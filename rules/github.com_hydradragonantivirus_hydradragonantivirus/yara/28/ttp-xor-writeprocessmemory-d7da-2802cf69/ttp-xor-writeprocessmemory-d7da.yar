rule TTP_XOR_WriteProcessMemory_d7da {
  strings:
    $key_d7da = { 80 a8 [2] b2 8a [2] b4 bf [2] 9a bf [2] a5 a3 }

  condition:
    any of them
}