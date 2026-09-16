rule TTP_XOR_WriteProcessMemory_0528 {
  strings:
    $key_0528 = { 52 5a [2] 60 78 [2] 66 4d [2] 48 4d [2] 77 51 }

  condition:
    any of them
}