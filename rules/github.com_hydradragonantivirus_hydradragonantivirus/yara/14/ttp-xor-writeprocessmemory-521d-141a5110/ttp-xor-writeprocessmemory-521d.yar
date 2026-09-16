rule TTP_XOR_WriteProcessMemory_521d {
  strings:
    $key_521d = { 05 6f [2] 37 4d [2] 31 78 [2] 1f 78 [2] 20 64 }

  condition:
    any of them
}