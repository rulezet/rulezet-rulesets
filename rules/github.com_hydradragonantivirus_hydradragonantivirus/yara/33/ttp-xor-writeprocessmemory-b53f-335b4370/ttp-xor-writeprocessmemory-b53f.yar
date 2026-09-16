rule TTP_XOR_WriteProcessMemory_b53f {
  strings:
    $key_b53f = { e2 4d [2] d0 6f [2] d6 5a [2] f8 5a [2] c7 46 }

  condition:
    any of them
}