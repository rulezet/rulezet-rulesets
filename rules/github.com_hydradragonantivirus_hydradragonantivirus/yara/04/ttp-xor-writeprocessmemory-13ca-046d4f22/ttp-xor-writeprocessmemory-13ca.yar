rule TTP_XOR_WriteProcessMemory_13ca {
  strings:
    $key_13ca = { 44 b8 [2] 76 9a [2] 70 af [2] 5e af [2] 61 b3 }

  condition:
    any of them
}