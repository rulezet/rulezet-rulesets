rule TTP_XOR_WriteProcessMemory_862f {
  strings:
    $key_862f = { d1 5d [2] e3 7f [2] e5 4a [2] cb 4a [2] f4 56 }

  condition:
    any of them
}