rule TTP_XOR_WriteProcessMemory_43da {
  strings:
    $key_43da = { 14 a8 [2] 26 8a [2] 20 bf [2] 0e bf [2] 31 a3 }

  condition:
    any of them
}