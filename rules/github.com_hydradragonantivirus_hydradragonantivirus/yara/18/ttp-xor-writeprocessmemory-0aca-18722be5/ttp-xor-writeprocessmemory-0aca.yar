rule TTP_XOR_WriteProcessMemory_0aca {
  strings:
    $key_0aca = { 5d b8 [2] 6f 9a [2] 69 af [2] 47 af [2] 78 b3 }

  condition:
    any of them
}