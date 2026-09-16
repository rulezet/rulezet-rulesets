rule TTP_XOR_WriteProcessMemory_035f {
  strings:
    $key_035f = { 54 2d [2] 66 0f [2] 60 3a [2] 4e 3a [2] 71 26 }

  condition:
    any of them
}