rule TTP_XOR_WriteProcessMemory_5618 {
  strings:
    $key_5618 = { 01 6a [2] 33 48 [2] 35 7d [2] 1b 7d [2] 24 61 }

  condition:
    any of them
}