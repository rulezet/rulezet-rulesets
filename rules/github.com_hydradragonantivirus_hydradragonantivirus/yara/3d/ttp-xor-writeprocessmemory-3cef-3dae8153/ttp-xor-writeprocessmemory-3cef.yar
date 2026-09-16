rule TTP_XOR_WriteProcessMemory_3cef {
  strings:
    $key_3cef = { 6b 9d [2] 59 bf [2] 5f 8a [2] 71 8a [2] 4e 96 }

  condition:
    any of them
}