rule TTP_XOR_WriteProcessMemory_ffef {
  strings:
    $key_ffef = { a8 9d [2] 9a bf [2] 9c 8a [2] b2 8a [2] 8d 96 }

  condition:
    any of them
}