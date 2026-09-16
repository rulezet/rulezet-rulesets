rule TTP_XOR_WriteProcessMemory_58ff {
  strings:
    $key_58ff = { 0f 8d [2] 3d af [2] 3b 9a [2] 15 9a [2] 2a 86 }

  condition:
    any of them
}