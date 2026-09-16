rule TTP_XOR_WriteProcessMemory_a01f {
  strings:
    $key_a01f = { f7 6d [2] c5 4f [2] c3 7a [2] ed 7a [2] d2 66 }

  condition:
    any of them
}