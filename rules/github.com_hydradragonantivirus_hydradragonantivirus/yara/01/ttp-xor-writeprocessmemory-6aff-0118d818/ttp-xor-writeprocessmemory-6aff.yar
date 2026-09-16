rule TTP_XOR_WriteProcessMemory_6aff {
  strings:
    $key_6aff = { 3d 8d [2] 0f af [2] 09 9a [2] 27 9a [2] 18 86 }

  condition:
    any of them
}