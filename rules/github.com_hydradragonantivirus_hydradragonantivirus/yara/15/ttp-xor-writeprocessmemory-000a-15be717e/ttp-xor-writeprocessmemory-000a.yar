rule TTP_XOR_WriteProcessMemory_000a {
  strings:
    $key_000a = { 57 78 [2] 65 5a [2] 63 6f [2] 4d 6f [2] 72 73 }

  condition:
    any of them
}