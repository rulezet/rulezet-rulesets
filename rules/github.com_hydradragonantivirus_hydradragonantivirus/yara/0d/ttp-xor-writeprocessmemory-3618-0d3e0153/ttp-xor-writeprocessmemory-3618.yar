rule TTP_XOR_WriteProcessMemory_3618 {
  strings:
    $key_3618 = { 61 6a [2] 53 48 [2] 55 7d [2] 7b 7d [2] 44 61 }

  condition:
    any of them
}