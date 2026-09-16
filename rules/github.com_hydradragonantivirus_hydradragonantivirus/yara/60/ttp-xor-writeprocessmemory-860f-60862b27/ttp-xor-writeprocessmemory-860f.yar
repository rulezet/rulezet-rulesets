rule TTP_XOR_WriteProcessMemory_860f {
  strings:
    $key_860f = { d1 7d [2] e3 5f [2] e5 6a [2] cb 6a [2] f4 76 }

  condition:
    any of them
}