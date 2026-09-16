rule TTP_XOR_WriteProcessMemory_b27a {
  strings:
    $key_b27a = { e5 08 [2] d7 2a [2] d1 1f [2] ff 1f [2] c0 03 }

  condition:
    any of them
}