rule TTP_XOR_WriteProcessMemory_246d {
  strings:
    $key_246d = { 73 1f [2] 41 3d [2] 47 08 [2] 69 08 [2] 56 14 }

  condition:
    any of them
}