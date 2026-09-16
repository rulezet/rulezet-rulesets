rule TTP_XOR_WriteProcessMemory_eb6d {
  strings:
    $key_eb6d = { bc 1f [2] 8e 3d [2] 88 08 [2] a6 08 [2] 99 14 }

  condition:
    any of them
}