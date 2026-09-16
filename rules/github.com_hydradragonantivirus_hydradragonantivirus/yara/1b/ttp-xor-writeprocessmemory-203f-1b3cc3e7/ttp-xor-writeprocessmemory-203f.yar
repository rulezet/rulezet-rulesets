rule TTP_XOR_WriteProcessMemory_203f {
  strings:
    $key_203f = { 77 4d [2] 45 6f [2] 43 5a [2] 6d 5a [2] 52 46 }

  condition:
    any of them
}