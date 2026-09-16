rule TTP_XOR_WriteProcessMemory_124a {
  strings:
    $key_124a = { 45 38 [2] 77 1a [2] 71 2f [2] 5f 2f [2] 60 33 }

  condition:
    any of them
}