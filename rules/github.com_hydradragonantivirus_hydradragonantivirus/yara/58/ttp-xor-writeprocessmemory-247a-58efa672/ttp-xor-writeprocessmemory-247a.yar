rule TTP_XOR_WriteProcessMemory_247a {
  strings:
    $key_247a = { 73 08 [2] 41 2a [2] 47 1f [2] 69 1f [2] 56 03 }

  condition:
    any of them
}