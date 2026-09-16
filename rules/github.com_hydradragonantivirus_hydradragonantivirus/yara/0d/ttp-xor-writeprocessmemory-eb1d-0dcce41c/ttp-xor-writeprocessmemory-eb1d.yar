rule TTP_XOR_WriteProcessMemory_eb1d {
  strings:
    $key_eb1d = { bc 6f [2] 8e 4d [2] 88 78 [2] a6 78 [2] 99 64 }

  condition:
    any of them
}