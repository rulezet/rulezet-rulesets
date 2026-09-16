rule TTP_XOR_WriteProcessMemory_39ef {
  strings:
    $key_39ef = { 6e 9d [2] 5c bf [2] 5a 8a [2] 74 8a [2] 4b 96 }

  condition:
    any of them
}