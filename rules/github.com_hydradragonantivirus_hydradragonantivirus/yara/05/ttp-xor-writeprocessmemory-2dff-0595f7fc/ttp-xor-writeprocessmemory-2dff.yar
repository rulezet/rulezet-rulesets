rule TTP_XOR_WriteProcessMemory_2dff {
  strings:
    $key_2dff = { 7a 8d [2] 48 af [2] 4e 9a [2] 60 9a [2] 5f 86 }

  condition:
    any of them
}