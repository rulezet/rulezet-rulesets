rule TTP_XOR_WriteProcessMemory_8618 {
  strings:
    $key_8618 = { d1 6a [2] e3 48 [2] e5 7d [2] cb 7d [2] f4 61 }

  condition:
    any of them
}