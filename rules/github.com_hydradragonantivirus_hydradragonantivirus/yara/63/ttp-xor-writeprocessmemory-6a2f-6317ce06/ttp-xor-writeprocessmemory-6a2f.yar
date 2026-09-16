rule TTP_XOR_WriteProcessMemory_6a2f {
  strings:
    $key_6a2f = { 3d 5d [2] 0f 7f [2] 09 4a [2] 27 4a [2] 18 56 }

  condition:
    any of them
}