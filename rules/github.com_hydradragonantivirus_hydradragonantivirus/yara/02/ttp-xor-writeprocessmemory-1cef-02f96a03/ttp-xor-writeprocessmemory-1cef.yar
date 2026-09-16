rule TTP_XOR_WriteProcessMemory_1cef {
  strings:
    $key_1cef = { 4b 9d [2] 79 bf [2] 7f 8a [2] 51 8a [2] 6e 96 }

  condition:
    any of them
}