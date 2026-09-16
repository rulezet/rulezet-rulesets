rule TTP_XOR_WriteProcessMemory_99ef {
  strings:
    $key_99ef = { ce 9d [2] fc bf [2] fa 8a [2] d4 8a [2] eb 96 }

  condition:
    any of them
}