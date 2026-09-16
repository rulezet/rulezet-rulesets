rule TTP_XOR_WriteProcessMemory_32ca {
  strings:
    $key_32ca = { 65 b8 [2] 57 9a [2] 51 af [2] 7f af [2] 40 b3 }

  condition:
    any of them
}