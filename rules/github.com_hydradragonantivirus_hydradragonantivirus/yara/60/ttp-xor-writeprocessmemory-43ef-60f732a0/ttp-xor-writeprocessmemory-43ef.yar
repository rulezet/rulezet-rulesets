rule TTP_XOR_WriteProcessMemory_43ef {
  strings:
    $key_43ef = { 14 9d [2] 26 bf [2] 20 8a [2] 0e 8a [2] 31 96 }

  condition:
    any of them
}