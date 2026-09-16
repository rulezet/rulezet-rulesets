rule TTP_XOR_WriteProcessMemory_ef3f {
  strings:
    $key_ef3f = { b8 4d [2] 8a 6f [2] 8c 5a [2] a2 5a [2] 9d 46 }

  condition:
    any of them
}