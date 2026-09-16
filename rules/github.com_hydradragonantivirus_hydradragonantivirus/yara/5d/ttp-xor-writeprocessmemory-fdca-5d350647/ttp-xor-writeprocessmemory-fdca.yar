rule TTP_XOR_WriteProcessMemory_fdca {
  strings:
    $key_fdca = { aa b8 [2] 98 9a [2] 9e af [2] b0 af [2] 8f b3 }

  condition:
    any of them
}