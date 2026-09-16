rule TTP_XOR_WriteProcessMemory_b5ca {
  strings:
    $key_b5ca = { e2 b8 [2] d0 9a [2] d6 af [2] f8 af [2] c7 b3 }

  condition:
    any of them
}