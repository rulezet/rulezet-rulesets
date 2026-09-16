rule TTP_XOR_WriteProcessMemory_1aca {
  strings:
    $key_1aca = { 4d b8 [2] 7f 9a [2] 79 af [2] 57 af [2] 68 b3 }

  condition:
    any of them
}