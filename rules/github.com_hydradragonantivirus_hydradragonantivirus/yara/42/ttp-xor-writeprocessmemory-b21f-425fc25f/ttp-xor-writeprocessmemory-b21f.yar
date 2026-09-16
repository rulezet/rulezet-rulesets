rule TTP_XOR_WriteProcessMemory_b21f {
  strings:
    $key_b21f = { e5 6d [2] d7 4f [2] d1 7a [2] ff 7a [2] c0 66 }

  condition:
    any of them
}