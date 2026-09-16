rule TTP_XOR_WriteProcessMemory_34ca {
  strings:
    $key_34ca = { 63 b8 [2] 51 9a [2] 57 af [2] 79 af [2] 46 b3 }

  condition:
    any of them
}