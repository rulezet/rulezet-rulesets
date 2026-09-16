rule TTP_XOR_WriteProcessMemory_7aec {
  strings:
    $key_7aec = { 2d 9e [2] 1f bc [2] 19 89 [2] 37 89 [2] 08 95 }

  condition:
    any of them
}