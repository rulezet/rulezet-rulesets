rule TTP_XOR_WriteProcessMemory_325d {
  strings:
    $key_325d = { 65 2f [2] 57 0d [2] 51 38 [2] 7f 38 [2] 40 24 }

  condition:
    any of them
}