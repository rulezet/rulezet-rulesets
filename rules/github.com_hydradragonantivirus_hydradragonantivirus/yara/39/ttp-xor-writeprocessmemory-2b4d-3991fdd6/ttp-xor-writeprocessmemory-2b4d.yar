rule TTP_XOR_WriteProcessMemory_2b4d {
  strings:
    $key_2b4d = { 7c 3f [2] 4e 1d [2] 48 28 [2] 66 28 [2] 59 34 }

  condition:
    any of them
}