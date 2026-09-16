rule TTP_XOR_WriteProcessMemory_364f {
  strings:
    $key_364f = { 61 3d [2] 53 1f [2] 55 2a [2] 7b 2a [2] 44 36 }

  condition:
    any of them
}