rule TTP_XOR_WriteProcessMemory_a618 {
  strings:
    $key_a618 = { f1 6a [2] c3 48 [2] c5 7d [2] eb 7d [2] d4 61 }

  condition:
    any of them
}