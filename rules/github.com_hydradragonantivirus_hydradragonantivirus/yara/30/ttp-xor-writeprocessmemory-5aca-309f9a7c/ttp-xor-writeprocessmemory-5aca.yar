rule TTP_XOR_WriteProcessMemory_5aca {
  strings:
    $key_5aca = { 0d b8 [2] 3f 9a [2] 39 af [2] 17 af [2] 28 b3 }

  condition:
    any of them
}