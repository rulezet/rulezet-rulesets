rule TTP_XOR_WriteProcessMemory_7cef {
  strings:
    $key_7cef = { 2b 9d [2] 19 bf [2] 1f 8a [2] 31 8a [2] 0e 96 }

  condition:
    any of them
}