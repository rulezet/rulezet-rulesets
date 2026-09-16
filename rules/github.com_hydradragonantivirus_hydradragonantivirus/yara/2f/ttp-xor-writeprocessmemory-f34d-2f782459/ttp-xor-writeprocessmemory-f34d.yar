rule TTP_XOR_WriteProcessMemory_f34d {
  strings:
    $key_f34d = { a4 3f [2] 96 1d [2] 90 28 [2] be 28 [2] 81 34 }

  condition:
    any of them
}