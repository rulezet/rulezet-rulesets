rule TTP_XOR_WriteProcessMemory_71da {
  strings:
    $key_71da = { 26 a8 [2] 14 8a [2] 12 bf [2] 3c bf [2] 03 a3 }

  condition:
    any of them
}