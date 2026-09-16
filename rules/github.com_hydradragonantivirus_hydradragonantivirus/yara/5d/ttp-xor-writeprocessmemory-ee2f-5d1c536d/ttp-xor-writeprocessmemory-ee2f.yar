rule TTP_XOR_WriteProcessMemory_ee2f {
  strings:
    $key_ee2f = { b9 5d [2] 8b 7f [2] 8d 4a [2] a3 4a [2] 9c 56 }

  condition:
    any of them
}