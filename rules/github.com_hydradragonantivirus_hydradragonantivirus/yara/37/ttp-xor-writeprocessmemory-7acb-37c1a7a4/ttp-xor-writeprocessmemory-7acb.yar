rule TTP_XOR_WriteProcessMemory_7acb {
  strings:
    $key_7acb = { 2d b9 [2] 1f 9b [2] 19 ae [2] 37 ae [2] 08 b2 }

  condition:
    any of them
}