rule TTP_XOR_WriteProcessMemory_000d {
  strings:
    $key_000d = { 57 7f [2] 65 5d [2] 63 68 [2] 4d 68 [2] 72 74 }

  condition:
    any of them
}