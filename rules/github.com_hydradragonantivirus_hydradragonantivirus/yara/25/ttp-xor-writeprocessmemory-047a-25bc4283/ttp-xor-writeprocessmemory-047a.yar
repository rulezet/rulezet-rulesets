rule TTP_XOR_WriteProcessMemory_047a {
  strings:
    $key_047a = { 53 08 [2] 61 2a [2] 67 1f [2] 49 1f [2] 76 03 }

  condition:
    any of them
}