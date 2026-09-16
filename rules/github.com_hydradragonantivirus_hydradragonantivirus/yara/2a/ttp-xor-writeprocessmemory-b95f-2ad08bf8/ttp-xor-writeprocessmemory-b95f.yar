rule TTP_XOR_WriteProcessMemory_b95f {
  strings:
    $key_b95f = { ee 2d [2] dc 0f [2] da 3a [2] f4 3a [2] cb 26 }

  condition:
    any of them
}