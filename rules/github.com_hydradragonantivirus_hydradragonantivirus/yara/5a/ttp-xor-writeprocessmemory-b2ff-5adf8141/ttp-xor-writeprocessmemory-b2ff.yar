rule TTP_XOR_WriteProcessMemory_b2ff {
  strings:
    $key_b2ff = { e5 8d [2] d7 af [2] d1 9a [2] ff 9a [2] c0 86 }

  condition:
    any of them
}