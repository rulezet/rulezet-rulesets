rule TTP_XOR_WriteProcessMemory_9618 {
  strings:
    $key_9618 = { c1 6a [2] f3 48 [2] f5 7d [2] db 7d [2] e4 61 }

  condition:
    any of them
}