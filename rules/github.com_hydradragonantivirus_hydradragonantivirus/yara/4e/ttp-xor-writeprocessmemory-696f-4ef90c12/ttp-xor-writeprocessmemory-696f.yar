rule TTP_XOR_WriteProcessMemory_696f {
  strings:
    $key_696f = { 3e 1d [2] 0c 3f [2] 0a 0a [2] 24 0a [2] 1b 16 }

  condition:
    any of them
}