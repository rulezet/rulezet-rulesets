rule TTP_XOR_WriteProcessMemory_a42f {
  strings:
    $key_a42f = { f3 5d [2] c1 7f [2] c7 4a [2] e9 4a [2] d6 56 }

  condition:
    any of them
}