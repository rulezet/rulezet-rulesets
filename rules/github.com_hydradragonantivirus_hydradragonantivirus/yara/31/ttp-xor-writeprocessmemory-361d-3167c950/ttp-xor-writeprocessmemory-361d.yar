rule TTP_XOR_WriteProcessMemory_361d {
  strings:
    $key_361d = { 61 6f [2] 53 4d [2] 55 78 [2] 7b 78 [2] 44 64 }

  condition:
    any of them
}