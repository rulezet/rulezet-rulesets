rule TTP_XOR_WriteProcessMemory_266f {
  strings:
    $key_266f = { 71 1d [2] 43 3f [2] 45 0a [2] 6b 0a [2] 54 16 }

  condition:
    any of them
}