rule TTP_XOR_WriteProcessMemory_faef {
  strings:
    $key_faef = { ad 9d [2] 9f bf [2] 99 8a [2] b7 8a [2] 88 96 }

  condition:
    any of them
}