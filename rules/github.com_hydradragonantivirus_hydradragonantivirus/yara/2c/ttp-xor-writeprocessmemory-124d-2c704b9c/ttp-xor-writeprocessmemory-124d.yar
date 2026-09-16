rule TTP_XOR_WriteProcessMemory_124d {
  strings:
    $key_124d = { 45 3f [2] 77 1d [2] 71 28 [2] 5f 28 [2] 60 34 }

  condition:
    any of them
}