rule TTP_XOR_WriteProcessMemory_090f {
  strings:
    $key_090f = { 5e 7d [2] 6c 5f [2] 6a 6a [2] 44 6a [2] 7b 76 }

  condition:
    any of them
}