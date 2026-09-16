rule TTP_XOR_WriteProcessMemory_d618 {
  strings:
    $key_d618 = { 81 6a [2] b3 48 [2] b5 7d [2] 9b 7d [2] a4 61 }

  condition:
    any of them
}