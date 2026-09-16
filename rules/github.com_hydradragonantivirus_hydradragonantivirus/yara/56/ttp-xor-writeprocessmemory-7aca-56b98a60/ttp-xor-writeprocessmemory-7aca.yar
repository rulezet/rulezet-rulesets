rule TTP_XOR_WriteProcessMemory_7aca {
  strings:
    $key_7aca = { 2d b8 [2] 1f 9a [2] 19 af [2] 37 af [2] 08 b3 }

  condition:
    any of them
}