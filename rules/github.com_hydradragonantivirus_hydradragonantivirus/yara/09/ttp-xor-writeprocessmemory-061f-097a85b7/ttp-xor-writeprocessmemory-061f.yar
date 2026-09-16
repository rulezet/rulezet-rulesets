rule TTP_XOR_WriteProcessMemory_061f {
  strings:
    $key_061f = { 51 6d [2] 63 4f [2] 65 7a [2] 4b 7a [2] 74 66 }

  condition:
    any of them
}