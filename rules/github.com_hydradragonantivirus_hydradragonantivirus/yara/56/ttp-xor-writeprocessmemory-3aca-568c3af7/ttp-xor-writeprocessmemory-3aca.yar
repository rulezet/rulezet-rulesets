rule TTP_XOR_WriteProcessMemory_3aca {
  strings:
    $key_3aca = { 6d b8 [2] 5f 9a [2] 59 af [2] 77 af [2] 48 b3 }

  condition:
    any of them
}